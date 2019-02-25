# Servidor Web
Proyecto para _Seguridad en aplicaciones Web_. \n
Implementación de un servidor mediante sockets y un _Web Application Firewall_ en `Node.js` 

## Integrantes

- Ferrusca Ortiz Jorge L.

## Instalación

- Para ejecutar, se debe contar al menos con **Node.js v8.x** o superior.

Para instalar: 

```sh
# Using Ubuntu
curl -sL https://deb.nodesource.com/setup_11.x | sudo -E bash -
sudo apt-get install -y nodejs

# Using Debian, as root
curl -sL https://deb.nodesource.com/setup_11.x | bash -
apt-get install -y nodejs
```

\*En caso de tener otra distribución, revisar el [README](https://github.com/nodesource/distributions/blob/master/README.md#debinstall) de instalación oficial.

- Verificar la instalación ejecutando `node -v`.

## Ejecución

El siguiente paso es clonar este repo vía [https](https://github.com/mp4-28/servidor-net.git) o [ssh](git@github.com:mp4-28/servidor-net.git) o bien, descargar el [ZIP](https://github.com/mp4-28/servidor-net/archive/master.zip).

Los archivos fundamentales para correr el proyecto son: 
- `index.js` (archivo principal)
- `anaylzer.js` (archivo de waf)
- `package.json` (archivo de instalación de dependencias)

Una vez descargado el proyecto, y en la misma ubicación del archivo **package.json**, ejecutar:
```sh
npm install
```
Esto instalará las dependencias necesarias para correr el **proyecto**

Con esto, ejecutar el proyecto con: 
```sh
node index.js [port] [logFile] [rules]
```

Opciones:
- `-p, --port 	Puerto por el cual se abrirá el socket (default: 8080)`
- `-l, --log 		Nombre del archivo donde se guardará el log de acceso`
- `-w, --waf 		Nombre del archivo de reglas (ej. reglas.txt)`

Por ejemplo, para correr con todas las opciones: 
```sh
node index.js -p 1234 -l=acceso.log -waf=reglas.txt
```