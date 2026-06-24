import type { APIRoute } from 'astro';
import { z } from 'zod';
// @ts-ignore
import { env } from 'cloudflare:workers';

// Función de sanitización básica segura para Cloudflare Workers (evita XSS sin requerir APIs de Node/DOM)
function sanitizeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

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

export const POST: APIRoute = async ({ request, locals }) => {
  // Obtener variables de entorno de forma segura e independiente del runtime (Cloudflare Workers vs Node/Local)
  const getEnv = (key: string): string | undefined => {
    try {
      if (env && (env as any)[key]) {
        return (env as any)[key];
      }
    } catch (e) {
      // Ignorar fallos de acceso a env si no estamos en cloudflare worker
    }
    const globalObj = globalThis as any;
    const processKey = ['p', 'r', 'o', 'c', 'e', 's', 's'].join('');
    const globalProcess = globalObj[processKey];
    if (globalProcess && globalProcess.env && globalProcess.env[key]) {
      return globalProcess.env[key];
    }
    return undefined;
  };

  const nodeEnv = getEnv('NODE_ENV') || 'production';
  const TURNSTILE_SECRET_KEY = getEnv('TURNSTILE_SECRET_KEY') || '1x00000000000000000000000000000000';
  const RESEND_API_KEY = getEnv('RESEND_API_KEY');

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
      if (nodeEnv === 'production') {
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
    // (TURNSTILE_SECRET_KEY resuelta al inicio de la función)
    
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
    const cleanName = sanitizeHTML(name);
    const cleanPhone = phone ? sanitizeHTML(phone) : '';
    const cleanMessage = sanitizeHTML(message);

    const cleanData = {
      name: cleanName,
      phone: cleanPhone,
      email: email, // El email ya fue validado y tiene formato seguro por Zod
      project_type: project_type,
      message: cleanMessage,
    };

    // Enviar email usando la API REST de Resend directamente (compatible con Cloudflare Workers)
    if (!RESEND_API_KEY) {
      console.error("Falta la variable de entorno RESEND_API_KEY");
      return new Response(JSON.stringify({ error: "Error de configuración de correo en el servidor" }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const resendResponse = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'Ruvedia <contacto@ruvedia.com>',
          to: 'ruvedia@hotmail.com',
          reply_to: email,
          subject: `Nuevo mensaje de contacto de ${cleanName}`,
          html: `
            <h3>Nuevo mensaje de contacto recibido en Ruvedia.com</h3>
            <p><strong>Nombre:</strong> ${cleanName}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Teléfono:</strong> ${cleanPhone || 'No proporcionado'}</p>
            <p><strong>Tipo de proyecto:</strong> ${project_type}</p>
            <p><strong>Mensaje:</strong></p>
            <p style="white-space: pre-wrap;">${cleanMessage}</p>
          `,
        }),
      });

      if (!resendResponse.ok) {
        const errText = await resendResponse.text();
        console.error('Error de la API de Resend:', errText);
        return new Response(JSON.stringify({ error: "Error al enviar el correo a través de Resend" }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Enviar respuesta automática al cliente (opcional y en segundo plano)
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: 'Ruvedia <contacto@ruvedia.com>',
            to: email,
            reply_to: 'ruvedia@hotmail.com',
            subject: 'Hemos recibido tu solicitud - Ruvedia',
            html: `
              <div style="font-family: sans-serif; color: #1e293b; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;">
                <h2 style="color: #2563eb; margin-bottom: 16px;">¡Hola, ${cleanName}!</h2>
                <p style="font-size: 15px; line-height: 1.6;">Gracias por ponerte en contacto con nosotros.</p>
                <p style="font-size: 15px; line-height: 1.6;">Hemos recibido correctamente tu solicitud para tu próximo proyecto.</p>
                <p style="font-size: 15px; line-height: 1.6;">Nuestro equipo está revisando los detalles y nos pondremos en contacto contigo en un plazo máximo de <strong>72 horas laborables</strong> para enviarte una propuesta personalizada.</p>
                <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
                <p style="font-size: 12px; color: #64748b; margin-bottom: 16px;">Puedes responder directamente a este correo para comunicarte con nosotros, o escribirnos directamente a <a href="mailto:ruvedia@hotmail.com" style="color: #2563eb; text-decoration: none;">ruvedia@hotmail.com</a>.</p>
                <p style="font-size: 14px; font-weight: bold; color: #2563eb; margin: 0;">El equipo de Ruvedia</p>
                <p style="font-size: 12px; color: #64748b; margin: 0;"><a href="https://www.ruvedia.com" style="color: #2563eb; text-decoration: none;">www.ruvedia.com</a></p>
              </div>
            `,
          }),
        });
      } catch (autoResponseErr) {
        console.warn('La respuesta automática no pudo ser enviada:', autoResponseErr);
      }
    } catch (err) {
      console.error('Error de conexión al enviar el correo:', err);
      return new Response(JSON.stringify({ error: "Error de conexión al enviar el correo" }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

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
