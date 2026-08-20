# TokenSteal

Proyecto educativo en C para estudiar el funcionamiento de los access tokens de Windows, la habilitación de privilegios, la duplicación de tokens y la creación de procesos bajo un contexto de seguridad distinto.

Autor: Eduardo Romera Martínez

> Uso exclusivo en laboratorios propios, entornos de formación y sistemas para los que se disponga de autorización expresa.

## Objetivo

El proyecto está pensado para comprender de forma práctica conceptos de seguridad interna de Windows relacionados con Windows Internals y post-explotación:

- access tokens;
- privilegios de Windows;
- `SeDebugPrivilege`;
- tokens primarios y de impersonación;
- `OpenProcessToken`;
- `DuplicateTokenEx`;
- `ImpersonateLoggedOnUser`;
- `CreateProcessWithTokenW`;
- integrity levels;
- procesos protegidos y PPL.

No pretende sustituir herramientas de pentesting existentes. Su valor principal es didáctico: mostrar qué APIs intervienen y qué ocurre en cada fase.

## Estructura

```text
TokenSteal/
├── README.md
├── .gitignore
└── src/
    └── tokensteal.c
```

El ejecutable precompilado se distribuirá mediante la sección **Releases** del repositorio y no se versionará junto con el código fuente.

## Flujo general

```text
Proceso actual
    |
    v
Abrir token propio
    |
    v
Comprobar / habilitar privilegios
    |
    v
Localizar un proceso SYSTEM accesible
    |
    v
Abrir su access token
    |
    v
DuplicateTokenEx
    |
    +----> Token primario duplicado
    |
    v
Impersonación del hilo
    |
    v
CreateProcessWithTokenW
    |
    v
Nuevo proceso con el token duplicado
```

## Requisitos

- Windows.
- MinGW-w64 o Microsoft Visual C++.
- Ejecución desde una consola elevada.
- Un contexto de seguridad que disponga de los privilegios necesarios.

El resultado depende de la versión y configuración de Windows. Determinados procesos pueden estar protegidos y rechazar el acceso incluso desde un proceso elevado.

## Compilación

### MinGW-w64

```bash
gcc src/tokensteal.c -o tokensteal.exe -ladvapi32
```

### Microsoft Visual C++

```cmd
cl /W4 src\tokensteal.c advapi32.lib
```

## Qué muestra el programa

Durante la ejecución se imprimen datos que ayudan a seguir el flujo:

- SID asociado al token;
- integrity level;
- tipo de token;
- privilegios habilitados;
- resultado de la habilitación de privilegios;
- proceso desde el que se obtiene el token;
- resultado de la duplicación e impersonación.

## APIs principales

| API | Función dentro del proyecto |
|---|---|
| `OpenProcessToken` | Abrir el token de un proceso |
| `LookupPrivilegeValue` | Resolver el LUID de un privilegio |
| `AdjustTokenPrivileges` | Habilitar privilegios presentes en el token |
| `GetTokenInformation` | Consultar usuario, privilegios, tipo e integrity level |
| `OpenProcess` | Obtener un handle sobre un proceso candidato |
| `DuplicateTokenEx` | Crear un nuevo token duplicado |
| `ImpersonateLoggedOnUser` | Aplicar un token al hilo actual |
| `CreateProcessWithTokenW` | Crear un proceso usando el token primario duplicado |

## Notas técnicas

`AdjustTokenPrivileges` no concede privilegios nuevos: solo puede modificar el estado de privilegios que ya estén presentes en el token.

La impersonación de un hilo y el token primario de un proceso son conceptos distintos. El proyecto muestra ambas ideas: primero puede establecer un contexto efectivo de hilo mediante impersonación y posteriormente utiliza un token primario para crear otro proceso.

La protección PPL puede impedir abrir determinados procesos o sus tokens. Por ese motivo el código prueba varios candidatos en lugar de depender de uno solo.

## Release

El binario precompilado se publicará en **Releases** para mantener el repositorio centrado en el código fuente. Si prefieres máxima trazabilidad, puedes compilar el proyecto directamente a partir de `src/tokensteal.c`.

## Aviso

Este proyecto documenta mecanismos de seguridad de Windows con fines educativos. Utilízalo únicamente en sistemas propios o expresamente autorizados.
