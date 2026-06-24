import type { APIRoute } from 'astro';
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

// Forzar que este endpoint se ejecute de forma dinámica en el servidor (modo SSR híbrido)
export const prerender = false;

// Esquema de validación estricta con Zod
const ContactSchema = z.object({
  name: z.string().min(2, { message: 'El nombre debe tener al menos 2 caracteres.' }).max(100),
  phone: z.string().max(30).optional().or(z.literal('')),
  email: z.string().email({ message: 'Debe ser una dirección de correo válida.' }),
  project_type: z.enum(['landing', 'corporativa', 'tienda', 'otro'], {
    errorMap: () => ({ message: 'Tipo de proyecto no válido.' }),
  }),
  message: z.string().min(10, { message: 'El mensaje debe detallar tu idea con al menos 10 caracteres.' }).max(2000),
  gdpr: z.literal(true, {
    errorMap: () => ({ message: 'Es obligatorio aceptar la política de privacidad.' }),
  }),
  // Campos de seguridad adicional
  website: z.string().max(100).optional().or(z.literal('')),
  turnstile_token: z.string().min(1, { message: 'Por favor, completa el desafío de seguridad.' }),
});

export const POST: APIRoute = async ({ request }) => {
  try {
    // 1. Mitigación de CSRF: Verificar la cabecera Origin o Referer
    const origin = request.headers.get('origin');
    const referer = request.headers.get('referer');
    const url = new URL(request.url);

    // En entornos locales o de producción, el origen debe coincidir con nuestro host
    if (origin) {
      const originUrl = new URL(origin);
      if (originUrl.host !== url.host) {
        return new Response(JSON.stringify({ error: 'Acceso no autorizado (Fallo de validación de origen)' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } else if (referer) {
      const refererUrl = new URL(referer);
      if (refererUrl.host !== url.host) {
        return new Response(JSON.stringify({ error: 'Acceso no autorizado (Fallo de validación de procedencia)' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } else {
      // Si no hay cabecera de origen en absoluto y no es local, bloquear
      if (process.env.NODE_ENV === 'production') {
        return new Response(JSON.stringify({ error: 'Acceso no autorizado (Falta origen de cabecera)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // 2. Parsear el cuerpo de la petición de forma segura
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Formato de cuerpo de mensaje no válido (JSON requerido)' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 3. Validar los datos con el esquema de Zod
    const validation = ContactSchema.safeParse(body);
    if (!validation.success) {
      const formattedErrors = validation.error.format();
      return new Response(
        JSON.stringify({
          error: 'Error de validación de campos',
          details: formattedErrors,
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const { name, phone, email, project_type, message, website, turnstile_token } = validation.data;

    // 4. Honeypot check: Si hay algún valor en website, es un bot
    if (website && website.trim() !== '') {
      console.warn('Registro bloqueado por Honeypot (bot detectado)');
      return new Response(JSON.stringify({ error: 'Acceso no autorizado (Detección de robot)' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 5. Validar el token de Turnstile contra la API de Cloudflare
    // Usamos el secret key de prueba si no hay una variable de entorno configurada
    const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x00000000000000000000000000000000';
    
    try {
      const turnstileVerifyResponse = await fetch(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `secret=${encodeURIComponent(TURNSTILE_SECRET_KEY)}&response=${encodeURIComponent(turnstile_token)}`,
        }
      );

      const turnstileResult = await turnstileVerifyResponse.json();
      if (!turnstileResult.success) {
        return new Response(
          JSON.stringify({
            error: 'Fallo en la validación del desafío anti-bot. Por favor, vuelve a cargarlo.',
          }),
          {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }
    } catch (err) {
      console.error('Error verificando captcha:', err);
      return new Response(JSON.stringify({ error: 'Error verificando el desafío de seguridad' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 6. Sanitizar las entradas de texto dinámico para prevenir XSS
    const cleanName = DOMPurify.sanitize(name);
    const cleanPhone = phone ? DOMPurify.sanitize(phone) : '';
    const cleanMessage = DOMPurify.sanitize(message);

    const cleanData = {
      name: cleanName,
      phone: cleanPhone,
      email: email, // El email ya fue validado y tiene formato seguro por Zod
      project_type: project_type,
      message: cleanMessage,
    };

    // Aquí iría el procesamiento (ej. guardar en DB, enviar por email con Resend/SendGrid/Nodemailer, etc.)
    console.log('Formulario de contacto recibido y sanitizado con éxito:', cleanData);

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Solicitud recibida correctamente de forma segura.',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('Error procesando formulario:', error);
    return new Response(JSON.stringify({ error: 'Error interno del servidor' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
