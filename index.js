/**
 * @author Jorge Ferrusca
 */
'use strict'

var net = require('net')
var fs = require('fs')
var argv = require('minimist')(process.argv.slice(2))
var path = require('path')
var exec = require('child_process').exec
require('dotenv').config()
let host = '127.0.0.1'
let port = argv['p'] || argv['port'] || 8080
let logFile = argv['l'] || argv['log'] || 'stdout'
let waf = argv['waf'] || false

/**
 * Valida las opciones ingresadas desde línea de comandos
 * @param {string|boolean} port - puerto de escucha
 * @param {string|boolean} logFile - nombre del archivo de logs
 * @param {string|boolean} waf - nombre del archivo del Web Application Firewall 
 */
let checkOptions = (port, logFile, waf) => {
  if(typeof port === 'boolean') {
    console.log('Debes especificar un valor para el puerto')
    process.exit(1)
  }
  if(typeof logFile === 'boolean') {
    console.log('Debes proporcionar un nombre de archivo para hacer el log')
    process.exit(1)
  }
  if(waf === true) {
    console.log('Debes proporcionar un nombre de archivo para las reglas del WAF ')
    process.exit(1)
  }
}

checkOptions(port, logFile, waf)
if (waf) {
  require('./analyzer.js')()
  readRules(waf)
}

/* response pattern */
// sock.write('HTTP/1.1 201 NO CONTENT\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello')

let response = ''
let principalHeader = ''
let allowedMethods = [
  'GET',
  'POST',
  'HEAD'
]
let mimeTypes = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpg',
  '.gif': 'image/gif',
  '.wav': 'audio/wav',
  '.mp4': 'video/mp4',
  '.woff': 'application/font-woff',
  '.ttf': 'application/font-ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.otf': 'application/font-otf',
  '.svg': 'application/image/svg+xml',
  '.txt': 'text/plain'
}
let cgis = [
  '.py', 
  '.pl', 
  '.cgi',
  '.php'
]
let commands = {
  '.py': 'python', 
  '.pl': 'perl',
  '.cgi': 'cgi',
  '.php': 'php'
}

/**
 * Registra un evento en el archivo de bitácora
 * @param {string} remoteHost - ip del cliente
 * @param {string} file - nombre del archivo bitácora
 * @param {object} tokens - headers recibidos en el request
 * @param {number} bytes - numero de bytes del response 
 */
function logEvent(remoteHost, file, data, tokens, bytes) {
  bytes = bytes || '0'
  if(file === 'stdout') {
    console.log('\nRequest:\n' + data.toString())
    console.log("\nResponse:\n" + response)
  } else {
    let row = 
      remoteHost + ' ' +
      '--' + ' ' +
      '[' + new Date().toISOString() + ']' + ' ' +
      // '"' + getRequestLine() + '"' +
      '\"' + principalHeader + '\"' + ' ' +
      getStatusCode() + ' ' +
      bytes + ' ' +
      '\"-\"' + ' ' + 
      '\"' + getHeader('User-Agent', tokens) + '\"'
    exec(
      'echo ' + row + ' >> ' + file,
      function (stderr, stdout, errorCode) {
        if(errorCode) console.log('Error al generar entrada de log en ' + file + ' ' + errorCode)
      }
    )
  }
}

/**
 * Genera un registro en el Log de auditoria (AUDIT.LOG)
 * @params timestamp de la fech
 * @params ip  cliente
 * @params puerto  cliente
 * @params puerto servidor
 * @params id   regla
 * @params descripcion   regla
 * @params peticion  cliente
 *
 */
function auditLog(remoteHost, remotePort, port, event, fullRequest) {
  let row = 
    '"' +   
    '[' + new Date().toISOString() + ']' + ' - ' +
    remoteHost + ':' + remotePort + ' - ' +
    'Puerto:' + port + ' - ' +
    'idRegla: ' + event.id + ' - ' +
    'Descripción: ' + event.descripcion + ' - Peticion: ' + 
    fullRequest.toString() +
    '\n*************************' +
    '"'
  exec(
    'echo ' + row + ' >> audit.log ',
    function (stderr, stdout, errorCode) {
      if(errorCode) console.log('Error al generar entrada de log en audit.log ' + errorCode)
    }
  )
}

const setEnviromentVariables = (remoteAddress, remotePort, tokens) => {
  process.env['NODE_ENV'] = 'production'
  process.env['DOCUMENT_ROOT'] = getEndPoint()
  process.env['HTTP_COOKIE'] = getHeader('Cookie', tokens)
  process.env['HTTP_REFERER'] = getHeader('Referer', tokens)
  process.env['CONTENT_LENGTH'] = getHeader('Content-Length', tokens)
  process.env['HTTP_USER_AGENT'] = getHeader('User-Agent', tokens)
  process.env['REMOTE_ADDR'] = remoteAddress
  process.env['REMOTE_PORT'] = remotePort
  process.env['REQUEST_METHOD'] = getRequestMethod()
  process.env['SERVER_NAME'] = getHeader('Host', tokens)
  process.env['SERVER_PORT'] = port
  process.env['SERVER_SOFTWARE'] = 'Apachenix 7.3'
}

/**
 * Parsea la cabecera principal en caso de que se haga una peticion GET
 * Por ejemplo: foo/?bar=baz terminaría en foo/
 * @param {object} tokens - headers recibidos en el request
 * (también recibe el header principal de tipo HTTP/1.0 /algo GET)
 * @returns {object} headers modificados, ya sin los datos de la peticion GET 
 */
const parseEndpoint = (tokens) => {
  let request = principalHeader.split(' ')[1]
  process.env['QUERY_STRING'] = ''
  if(request.includes('?')){ //request got GET params
    process.env['QUERY_STRING'] = request.split('?')[1] + '\n' //+ un salto de linea
    principalHeader = 
      principalHeader.split(' ')[0] 
      + ' ' 
      + request.split('?')[0]
      + ' ' 
      + principalHeader.split(' ')[2]
  }
  return tokens
}

const getRequestPayload = (request) => {
  return request.split('\r\n\r\n')[1] || 0
}


/**
 * Forma un header para la respuesta (response)
 * @param {string} key - nombre del header (ejemplo: content-encoding, Content-type)
 * @param {string} value - el valor de dicha cabecera
 */
function globalSetResponse(key, value) {
  response += key + ': ' + value
  setBreakLine()
}

function setContent(payload) {
  setBreakLine() //setting last breakline in order to finish response
  response += payload
}

const getHeader = (caption, tokens) => {
  return tokens[caption] || ''
}

/**
 * Parsea la petición completa
 * @param {string} data - la cadena completa de la petición
 * @returns {object} la petición ahora mapeada a un objeto (clave-valor) 
 */
function parseRequest(data) {
  let tokens = data.split(": ")
  let arr = []
  let maped = {}
  // console.log(tokens)
  tokens.forEach(t => {
    arr.push(t.split('\r\n')[0])
    arr.push(t.split('\r\n')[1])
  })
  principalHeader = arr[0]
  arr.splice(0,1)
  for(let a = 0; a < arr.length-1; ++a) {
    maped[arr[a]] = arr[++a]
  }
  // console.log("Mapeado:\n" + maped)
  return maped
}

function getRequestMethod() {
  return principalHeader.split(' ')[0]
}

function getEndPoint() {
  return '.' + principalHeader.split(' ')[1]
}

function getHttpVersion() {
  return principalHeader.split(' ')[2]
}

function setHttpVersion() {
  response = getHttpVersion()
}

function setstatusCode(code) {
  response += ' ' + code
  setBreakLine()
}

function getStatusCode() {
  return response.split(' ')[1]
}

function setBreakLine() {
  response += '\r\n'
}

/**
 * Ejecuta un archivo, y envía su salida al cliente
 * @param {string} filepath - la ubicacion del recurso solicitado
 * @param {string} payload - cuerpo de petición POST, en caso de existir
 * @returns {Promise} el resultado del intento de ejecutar el archivo  
 */
const executeFile = (filePath, payload) => {
  let extname = String(path.extname(filePath)).toLowerCase()
  let command = commands[extname]
  return new Promise((resolve, reject) => {
    if (extname === '.cgi') {
      let child = exec(filePath,
        function (stderr, stdout, errorCode) {
          if(stderr || errorCode) {
            setstatusCode('500 Internal Server Error')
            globalSetResponse('Content-Type', 'text/plain')
            setContent("Error al intentar ejecutar " + filePath)
            resolve(true)
            return
          } else if (stdout) {
            setstatusCode('201 OK')
            globalSetResponse('Content-Type', 'text/html')
            setContent(stdout)
            resolve(true)
            return
          }
        }
      )
      if(getRequestMethod() === 'POST') child.stdin.write(payload)
    } else {
      let spawn = require("child_process").spawn
      let process = spawn(
        command,
        [
          filePath,
        ] 
      ) 
      process.stdout.on('data', function(data) { 
        // console.log(data.toString())
        setstatusCode('200 OK')
        globalSetResponse('Content-Type', 'text/plain')
        setContent(data.toString())
        resolve(true)
      })
    }
  })
}

/**
 * Suministra un recurso al cliente
 * @param {string} filepath - la ubicacion del recurso solicitado
 * @param {string} method - el tipo de método empleado en la petición
 * @returns {Promise} el resultado del intento de abrir el archivo
 */
const serveFile = (filePath, method) => {
  return new Promise ((resolve, reject) => {
    let extname = String(path.extname(filePath)).toLowerCase()
    let contentType = mimeTypes[extname] || 'application/octet-stream'
    if(filePath === './') {
      setstatusCode('200 OK')
      globalSetResponse('Content-Type', 'text/plain')
      if(method !== 'HEAD') setContent('Bienvenido :)')
      resolve(true)
      return 0
    }
    if(cgis.includes(extname)) {
      resolve(executeFile(filePath, null))
    }
    else {
      fs.readFile(filePath, function(error, content) {
        if (error) {
          if(error.code == 'ENOENT') {
            // console.log('File not found')
            setstatusCode('404 File Not Found')
            if(method === 'GET') {
              globalSetResponse('Content-Type', 'text/plain')
              setContent('No Existe el archivo: ' + filePath)
            }
            resolve(true)
          }
          else if(error.code === 'EACCES') {
            setstatusCode('403 Forbidden')
            if(method === 'GET') {
              globalSetResponse('Content-Type', 'text/plain')
              setContent('No se tienen permisos suficientes (code: ' + error.code + ')')
            }
            resolve(true)
          }
          else {
            setstatusCode('500 Internal Server Error')
            if(method === 'GET') {
              globalSetResponse('Content-Type', 'text/plain')
              setContent('No se pudo leer el archivo (code: ' + error.code + ')')
            }
          }
          resolve(true)
        }
        else {
          setstatusCode('200 OK')
          if(method === 'GET') {
            globalSetResponse('Content-Type', contentType)
            setContent(content)
          }
          resolve(true)
          return 0
        }
      })
    }
  })
}

/**
* AGENTE_USUARIO: El agente de usuario de la petición.
* METODO: El método HTTP utilizado.
* RECURSO: El recurso al que se quiere acceder con la petición
* CUERPO: El cuerpo de la petición.
* CLIENTE_IP: La dirección IP del cliente.
* CABECERAS_VALORES: Los valores de las cabeceras.
* CABECERAS_NOMBRES: Los nombres de las cabeceras.
* CABECERAS: Nombres y valores de las cabeceras.
* PETICION_LINEA: La primer línea de la petición
* COOKIES: Las cookies.
*/


/**
 * Envia la petición al WAF
 * @param {string} remoteAddress - la direccion IP del cliente
 * @param {object} tokens - la petición en forma de objeto
 * @param {string} payload - cuerpo de petición POST, en caso de existir
 * @returns {Array} el resultado del analisis de la petición
 */
const sendToAnalyzer = (remoteAddress, tokens, payload) => {
  return analyzeRequest(
    getHeader('User-Agent', tokens),
    getRequestMethod(),
    getEndPoint(),
    payload,
    remoteAddress,
    Object.values(tokens),
    Object.keys(tokens),
    tokens,
    principalHeader,
    getHeader('Cookie', tokens)
  )
}

const closeResponse = (code, status) => {
  setstatusCode(code + ' ' + status)
}

/**
 * Crea el servidor en el puerto especificado y pone a la escucha el socket.
 * @param {Function} Un socket que está a la escucha cuando 
 * se abre (genera) una nueva conexión y cuando se cierra la misma
 */   
net.createServer(function(sock) {
  sock.on('data', function(data) {
    let remoteAddress = sock.remoteAddress.split('::ffff:')[1] || '127.0.0.1'
    console.log(remoteAddress)
    console.log('Conexión entrante en: ' + remoteAddress + '...')
    /** Parsing string to array of tokens **/
    let tokens = parseRequest(data.toString())
    let payload = getRequestPayload(data.toString())
    /** parsing endpoint like /directorio/foo.bar?param=value **/
    tokens = parseEndpoint(tokens)
    /** getting headers and information **/
    setEnviromentVariables(remoteAddress, sock.remotePort, tokens)
    /** setting HTTP 1.0, 2.0, 2.1 for response **/
    setHttpVersion()
    /** if METHOD isn't GET, POST or HEAD **/
    if(!allowedMethods.includes(getRequestMethod())) {
      setstatusCode('405 Method Not Allowed')
      globalSetResponse('Content-Type', 'text/plain')
      setContent('Método no permitido')
      logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
      sock.end(response)
      sock.destroy()
    }
    if (waf) {
      let actions = sendToAnalyzer(remoteAddress, tokens, payload)
      actions.forEach(a => {
        auditLog(remoteAddress, sock.remotePort, port, a, data) //Se auditan todos los matches
        if(!sock.destroyed) {
          if(a.action === 'ignorar') {
            sock.end()
          } 
          else if(a.action === 'codigo:403') {
            closeResponse('403', 'Forbidden')
            sock.end(response)
          } 
          else if (a.action === 'codigo:404') {
            closeResponse('404', 'File Not Found')
            sock.end(response)
          } 
          else if (a.action === 'codigo:500') {
            closeResponse('500', 'Internal Server Error')
            sock.end(response)
          } 
          else {
            console.log("Hubo un match en el WAF, pero no sé qué responderle al cliente...")
            sock.end()
          }
          sock.destroy()
        }
      })
    }
    if (!sock.destroyed) {
      /** Trying to serve files **/
      if(getRequestMethod() === 'GET' || getRequestMethod() === 'HEAD') {
        serveFile(getEndPoint(), getRequestMethod()).then(() => { 
          // globalSetResponse('Connection', 'close') //closing response (optional)
          sock.end(response)
          logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
        })
      } 
      /** Trying to get POST params **/
      else if (getRequestMethod() === 'POST') {
        let extname = String(path.extname(getEndPoint())).toLowerCase()
        if (extname === '.cgi') {
          process.env['QUERY_STRING'] = ''
          executeFile(getEndPoint(), payload).then(
            (success) => {
              sock.end(response)
              logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
            }, (err) => {
              setstatusCode('500 Internal Server Error')
              globalSetResponse('Content-Type', 'text/plain')
              setContent('Error al ejecutar el método POST')
              sock.end(response)
              logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
            }
          )
        } else {
          setstatusCode('201 NO CONTENT')
          globalSetResponse('Content-Type', 'text/plain')
          setContent('Ejecución de POST exitosa')
          sock.end(response)
          logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
        } 
      }
    } else {
      //logging requests filtered by waf
      logEvent(remoteAddress, logFile, data, tokens, sock.bytesWritten)
    }
  })
  
  //connection is closed
  sock.on('close', function(data) {
    console.log('Conexión cerrada en: ' + (sock.remoteAddress.split('::ffff:')[1] || '127.0.0.1') +' '+ sock.remotePort + '...')
  })
    
}).listen(port)
console.log('Servidor escuchando en ' + host +':'+ port)