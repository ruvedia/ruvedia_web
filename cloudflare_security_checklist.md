# Guía y Lista de Verificación de Seguridad para Despliegues en Cloudflare

Esta guía sirve como plantilla para asegurar que los desarrollos en Astro (y otras tecnologías web modernas) se desplieguen con los máximos estándares de seguridad y rendimiento en **Cloudflare** (Pages / Workers).

---

## 1. Pautas de Seguridad en la Aplicación (Antes del Despliegue)

### A. Validación e Integridad de Datos
- [x] **Validación en Servidor con Zod**: Validar estrictamente todas las entradas de datos en endpoints y formularios en el servidor.
- [x] **Sanitización de Datos**: Utilizar `isomorphic-dompurify` para desinfectar cualquier entrada del usuario antes de utilizarla en elementos como `set:html`.
- [x] **Tokens CSRF**: Implementar verificación de origen (`Origin` / `Referer`) o tokens CSRF en peticiones de tipo `POST`, `PUT` y `DELETE`.
- [ ] **Protección CSRF Nativa de Astro**: Habilitar `security.csrfProtection` en `astro.config.mjs` si se usa renderizado SSR.
- [ ] **Inyección de Consultas (SQL/NoSQL)**: Utilizar siempre consultas parametrizadas o un ORM (como Prisma o Drizzle) para evitar inyecciones de código en la base de datos.
- [ ] **Gestión Segura de Archivos**: Si se permiten subidas de archivos, limitar tamaño y extensión, verificar tipo MIME y guardarlos fuera del servidor de origen (ej. S3 o Cloudinary).

### B. Gestión de Credenciales y Variables de Entorno
- [ ] **Variables de Entorno Privadas**: Asegurarse de que ninguna variable que contenga tokens, contraseñas o claves privadas tenga el prefijo `PUBLIC_` (o equivalente que las exponga al cliente).
- [ ] **Secretos en Cloudflare**: Configurar las claves y tokens de API en el panel de control de Cloudflare (en la sección *Settings > Environment Variables* del proyecto de Pages) en lugar de subirlas al repositorio de Git.

### C. Navegación y Enlaces
- [ ] **Enlaces Externos Seguros**: Asegurar que todos los enlaces salientes (`<a target="_blank">`) incluyan `rel="noopener noreferrer"` para mitigar ataques de tabnabbing.

---

## 2. Configuración Esencial en Cloudflare (En Producción)

### A. Seguridad SSL/TLS
- [ ] **Modo de Encriptación Completo (Full / Strict)**: Asegurar que el tráfico entre Cloudflare y el servidor de origen (si existe) esté completamente encriptado.
- [ ] **HTTPS Siempre Activo (Always Use HTTPS)**: Forzar la redirección automática de peticiones HTTP a HTTPS.
- [ ] **HSTS (HTTP Strict Transport Security)**: Habilitar HSTS para obligar a los navegadores a comunicarse únicamente mediante conexiones seguras durante un tiempo determinado.

### B. Reglas de Cortafuegos y WAF (Web Application Firewall)
- [ ] **Activación del WAF**: Habilitar las reglas gestionadas de Cloudflare para mitigar ataques comunes (SQLi, XSS, etc.).
- [ ] **Protección Anti-DDoS**: Asegurar que la mitigación automática de DDoS está activa para el dominio.
- [ ] **Desafíos de Seguridad (Managed Challenge)**: Configurar desafíos en rutas críticas (ej. `/admin` o endpoints de inicio de sesión) para bloquear bots automáticos sin frustrar a los usuarios reales.

### C. Cabeceras de Seguridad HTTP
Configurar cabeceras de respuesta seguras mediante las reglas de transformación de Cloudflare (*Transform Rules*) o funciones del servidor:
- [ ] **Content-Security-Policy (CSP)**: Restringir de dónde pueden cargarse los recursos (scripts, imágenes, estilos) para evitar inyecciones XSS.
- [ ] **X-Frame-Options**: Evitar que el sitio sea incrustado en iframes ajenos (previniendo *Clickjacking*). Usar `DENY` o `SAMEORIGIN`.
- [ ] **X-Content-Type-Options**: Prevenir el husmeo de tipos MIME estableciéndolo en `nosniff`.
- [ ] **Referrer-Policy**: Controlar cuánta información de referencia se envía en los enlaces salientes (ej. `strict-origin-when-cross-origin`).

---

## 3. Pasos para Verificar que Todo Está Bien Hecho

Una vez desplegada la web, sigue estos pasos para comprobar la correcta implementación de la seguridad:

### Paso 1: Auditoría Externa de Cabeceras
Visita herramientas públicas gratuitas de análisis de seguridad para escanear tu dominio:
- **Mozilla Observatory** ([observatory.mozilla.org](https://observatory.mozilla.org)): Evalúa las cabeceras HTTP de tu sitio. Debe otorgarte una calificación alta si la CSP, HSTS y demás cabeceras están bien configuradas.
- **Security Headers** ([securityheaders.com](https://securityheaders.com)): Te proporcionará una nota (de la F a la A+) según las cabeceras HTTP configuradas en Cloudflare.

### Paso 2: Comprobación del Tráfico Cifrado
1. Abre tu sitio web en el navegador.
2. Haz clic en el candado de la barra de direcciones.
3. Asegúrate de que indica que la conexión es segura y que el certificado SSL/TLS es válido y emitido por Cloudflare.

### Paso 3: Inspección de Variables de Entorno en el Navegador
1. Abre las herramientas de desarrollo de tu navegador (`F12` o clic derecho -> *Inspeccionar*).
2. Ve a la pestaña **Consola** o **Red** (Network).
3. Asegúrate de que no haya ninguna variable crítica o token privado visible en el código fuente descargado por el navegador ni en las peticiones de red iniciales.

### Paso 4: Intento de Acceso por HTTP no Seguro
1. Intenta acceder manualmente escribiendo `http://tudominio.com` en la barra de direcciones.
2. Confirma que eres redirigido inmediatamente a `https://tudominio.com`.

---

## 4. Vulnerabilidades Comunes a Verificar (Lista de Comprobación Manual)

Esta lista sirve para revisar de forma manual y uno a uno los archivos de tu proyecto para prevenir fallos típicos de seguridad:

### [ ] Inyección de Scripts en Sitios Cruzados (XSS)
- [ ] Buscar en los archivos de la aplicación si se utiliza la directiva `set:html={...}`.
- [ ] Confirmar que, si se usa `set:html`, el origen del dato sea una constante estática o que el valor pase por la función de sanitización de `isomorphic-dompurify` en el servidor antes de renderizarse.
- [ ] Comprobar si existen componentes de React/Preact que utilicen `dangerouslySetInnerHTML`.
- [ ] Evitar la concatenación de variables directamente dentro de scripts de cliente `<script>` sin antes codificarlas o validarlas.

### [ ] Control de Acceso Incompleto
- [ ] Revisar todos los archivos dentro de `src/pages/api/` o endpoints con extensiones `.json.ts` o `.ts`.
- [ ] Verificar que cada endpoint que realice cambios o entregue información sensible compruebe las cabeceras de autorización, tokens de sesión o cookies antes de responder.
- [ ] Confirmar que las páginas protegidas no solo oculten los elementos en el lado cliente sino que restrinjan el acceso directamente desde el servidor durante el renderizado.

### [ ] Fuga de Credenciales y Claves Privadas
- [ ] Inspeccionar el archivo `.env` del proyecto.
- [ ] Asegurar que ninguna variable que contenga contraseñas, tokens de Shopify, tokens de base de datos o claves secretas comience con el prefijo `PUBLIC_`.
- [ ] Buscar en el proyecto archivos JS/TS que importen o muestren en la consola del cliente variables sensibles (evitar `console.log(import.meta.env.CLAVE_SECRETA)`).

### [ ] Vulnerabilidad a CSRF (Falsificación de Peticiones)
- [ ] Verificar en endpoints de mutación (`POST`, `PUT`, `DELETE`) que se valide el origen de la petición comparando las cabeceras `Origin` o `Referer` contra el host permitido.
- [ ] Implementar validación estricta de cookies de sesión con directivas `SameSite=Lax` o `SameSite=Strict`.

### [ ] Configuración Insegura y Respuestas Erradas
- [ ] Asegurar que los mensajes de error en producción no devuelvan trazas completas de la base de datos o errores internos del servidor.
- [ ] Comprobar que en Cloudflare las opciones de "Always Use HTTPS" y "HSTS" estén activadas.

### [ ] Falta de Validación en Datos de Entrada
- [ ] Buscar los archivos donde se procesen entradas de formularios o peticiones JSON (`request.json()` o `Astro.request.formData()`).
- [ ] Comprobar que todos los campos del formulario estén tipados y validados usando esquemas estrictos de Zod (ej. `schema.safeParse()`) antes de cualquier procesamiento en la base de datos o en servicios de terceros.

### [ ] Enlaces Externos No Protegidos
- [ ] Buscar etiquetas `<a ... target="_blank">` en los componentes.
- [ ] Confirmar que incluyen `rel="noopener noreferrer"`.

### [ ] Dependencias Vulnerables y Actualización Continua (npm)
- [ ] **Auditoría de vulnerabilidades:** Ejecutar `npm audit` periódicamente para identificar y resolver parches de seguridad rápidos con `npm audit fix`.
- [ ] **Chequeo de versiones desactualizadas:** Ejecutar `npm outdated` para verificar qué paquetes tienen actualizaciones pendientes.
- [ ] **Mantenimiento del framework principal:** Revisar y actualizar con frecuencia el paquete `astro` y sus integraciones oficiales (ej. `@astrojs/cloudflare`) para mantener parches de rendimiento y estabilidad al día.
- [ ] **Librerías críticas de seguridad:** Asegurar que `isomorphic-dompurify` y `zod` se mantengan siempre en sus versiones más recientes para evitar fugas y ataques XSS/Inyecciones.
- [ ] **Automatización con Dependabot (Opcional):** Si el proyecto está en GitHub, habilitar la alerta de Dependabot para recibir avisos automáticos de dependencias vulnerables.

### [ ] Seguridad de las Cuentas e Infraestructura
- [ ] Activar la verificación en dos pasos (2FA/MFA) en el proveedor del dominio, Cloudflare, GitHub y plataforma de hosting.
- [ ] Seguir el principio de menor privilegio al otorgar permisos de acceso a colaboradores en estas cuentas.

