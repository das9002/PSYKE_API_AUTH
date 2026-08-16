# AuthAPI — API de Autenticación Independiente

API de autenticación **totalmente independiente** de la API de servicios de negocio (`PTC`), diseñada según los lineamientos de la Rúbrica de Evaluación y el Módulo 2 del curso (Arquitectura de Capas, RESTful, JWT y Seguridad).

| Propiedad | Valor |
|---|---|
| **Puerto** | `8081` (la API de negocio `PTC` usa `8080`) |
| **Base de datos** | Oracle (compartida con `PTC`: tabla `USUARIOS`) |
| **Encriptación** | Argon2id (`Argon2PasswordEncoder`) |
| **Token** | JWT HS256 (JJWT 0.11.5) |
| **Java** | 17 |
| **Spring Boot** | 4.1.0 |

## Estructura de paquetes (por capas)

```
PsykeP.AuthAPI
├── AuthApiApplication.java      → Punto de entrada (carga el .env)
├── config/                      → SecurityConfig, ApplicationConfig, CorsConfig
├── controllers/                 → AuthController (login, register, me)
├── services/                    → AuthService (@Transactional(readOnly=true) en clase)
├── repositories/                → UsuarioRepository
├── entities/                    → Usuario (tabla USUARIOS)
├── dtos/                        → LoginRequestDTO, RegisterRequestDTO, AuthResponseDTO, UsuarioDTO
├── exceptions/                  → Excepciones personalizadas + GlobalExceptionHandler
├── models/                      → ErrorResponse (formato uniforme de errores)
└── security/                    → JwtService, JwtAuthenticationFilter
```

## Requisitos previos

1. **Java 17** instalado (`java -version`).
2. **Oracle** en ejecución (`localhost:1521/XEPDB1`) con el esquema cargado:
   - Ejecuta `BD\PSYKE_BD_FULL.sql` del proyecto `PTC` (crea `USUARIOS` y demás tablas).
   - El perfil del usuario se define con `USU_TIPO_USUARIO` (`ESTUDIANTE` o `PSICOLOGO`).
3. Las credenciales de BD se leen del archivo local `.env` (ya configurado con la BD de `DIEGO_PSYKE`).

## Cómo ejecutarla

Desde la raíz de `AuthAPI` (usa el Maven wrapper incluido):

```bash
.\mvnw.cmd spring-boot:run
```

La API quedará disponible en: **http://localhost:8081**

> Para correr ambas APIs al mismo tiempo, solo inicia también `PTC` (puerto 8080). Comparten la misma base de datos Oracle, no el mismo puerto.

## Endpoints RESTful

### POST /api/auth/register — Crear usuario (201 Created)

```json
{
  "correo": "juan@mail.com",
  "contrasena": "ClaveSegura123",
  "tipoUsuario": "ESTUDIANTE"
}
```

### POST /api/auth/login — Iniciar sesión (200 OK)

```json
{
  "correo": "juan@mail.com",
  "contrasena": "ClaveSegura123"
}
```

Respuesta: `{ "token": "eyJ...", "tipoToken": "Bearer", "idUsuario": 1, "correo": "...", "tipoUsuario": "ESTUDIANTE", "expiraEn": 86400000 }`

### GET /api/auth/me — Perfil del usuario autenticado (200 OK, protegido con JWT)

```
Authorization: Bearer <token>
```

## Códigos de estado HTTP (RESTful)

| Código | Caso |
|---|---|
| `200 OK` | Login y consulta de perfil exitosos |
| `201 Created` | Registro de usuario exitoso |
| `400 Bad Request` | Errores de validación de campos (`@Valid`) |
| `401 Unauthorized` | Credenciales inválidas / token inválido o expirado |
| `403 Forbidden` | Cuenta inactiva o bloqueada |
| `404 Not Found` | Usuario no encontrado en `/me` |
| `409 Conflict` | Correo ya registrado |

## Cumplimiento de la Rúbrica

- **Proyecto independiente y puerto separado:** nuevo proyecto `AuthAPI` corriendo en `8081` vs `8080` de `PTC`.
- **Seguridad y encriptación:** login por correo + contraseña, hash Argon2id y token JWT.
- **Capa de excepciones en Service:** los servicios lanzan excepciones personalizadas (`CredencialesInvalidasException`, `CorreoYaRegistradoException`, etc.) con `orElseThrow` — **nunca retornan `null`** — y `GlobalExceptionHandler` las traduce a códigos HTTP.
- **Manejo de transacciones:** `@Transactional(readOnly = true)` a nivel de clase en `AuthService`; `registrar()` y `login()` se sobrescriben con `@Transactional`.
- **Relaciones JPA:** carga perezosa `FetchType.LAZY` en todas las relaciones; la API solo expone la entidad `USUARIOS` alineada con la base de datos Oracle.
- **Estándares RESTful:** verbos HTTP correctos (`POST` para login/registro, `GET` para perfil) con códigos de estado apropiados (`201`, `400`, `401`, `403`, `404`, `409`).