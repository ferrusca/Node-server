/**
 *
 * Módulo para el Web Application Firewall
 */
module.exports = function() {
var fs = require('fs')

/**
 rules = [
		0: {
				'regla': n, 
				'variables: METODO, RECURSO',
				'operador': iregex, 
				'expresion': "string",
				'descripcion': "descripcion",
				'accion': [codigo:{403:404:500}|ignorar]
			}
	  1: {...}
	  2: {...}
 ]

**/

//Examples
// curl 127.0.0.1:8080/hola.cgi -d "<script> </script>" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Host: 127.0.0.1:1235"

	const variableArgumento = [
		'AGENTE_USUARIO',
		'METODO',
		'RECURSO',
		'CUERPO',
		'CLIENTE_IP',
		'CABECERAS_VALORES',
		'CABECERAS_NOMBRES',
		'CABECERAS',
		'PETICION_LINEA',
		'COOKIES',
	]

	const RULE_LENGTH = 5
	var rules = []
	const indexes = [
		'regla',
		'variables',
		'operador',
		// 'expr',
		'descripcion',
		'accion'
	]

	const verificaExistencia = (variables) => {
		variables.split('|').forEach(v => {
			if(!variableArgumento.includes(v)) {
				console.log('METODO "' + v + '" no encontrado. Verifique la sintaxis de las Reglas del WAF')
				process.exit(1)
			}
		})
	}

	/**
	 * Guarda cada regla como elemento de un arreglo
	 * @param {Array} lineTokens - cada uno de los elementos de la regla
	 * que están separados por el delimitador ';'
	 */
	const setRules = (lineTokens) => {
		let obj = {}
		lineTokens.forEach((lt, i) => {
			if (i === 1) {
				verificaExistencia(lt)
			} 
			if(i === 0) {
				obj[indexes[i]] = lt.split('->')[1]
			} else if (i === 2) {
				obj[indexes[i]] = lt.split(':')[0]
				let aux = lt.split(':')[1]
				obj['expresion'] = aux.slice(1,-1)
			} else {
				obj[indexes[i]] = lt
			}
		})
		rules.push(obj)
		obj = {}
	}

	/**
	 * Obtiene los tokens de cada regla dada
	 * @param {Array} rules - las reglas que se obtuvieron del archivo
	 */
	const parseRules = (rules) => {
		rules.forEach((r, i) => {
			let lineTokens = r.split(';')
			if(lineTokens.length !== RULE_LENGTH) {
				console.log('Error al leer las reglas de WAF, verifique la sintaxis de la linea: ' + (i+1))
				process.exit(1)
			}
			setRules(lineTokens)
		})
	}


	/**
 	 * Verifica que no existan reglas con ID duplicado
   * @param {Array} rules - reglas del WAF
 	 */
	const avoidDuplicate = (rules) => {
		let numbers = []
		if(rules)
		rules.forEach(r => {
			numbers.push(r.regla)
		})
		numbers = numbers.sort()	
		for (let i = 0; i < numbers.length - 1; i++) {
	    if (numbers[i + 1] == numbers[i]) {
	    	console.log('Error, reglas con id duplicado (' + numbers[i] + ')')
	      process.exit(1)
	    }
		}
	}


	/**
   * Lee las reglas de un archivo
   * @param {string} file - nombre del archivo de reglas
   */
	this.readRules = (file) => {
		fs.readFile(file, function(error, content) {
	    if (error) {
	      if(error.code == 'ENOENT') {
	        console.log('File not found: ' + file)
	        process.exit(1)
	      }
	      else if(error.code === 'EACCES') {
	      	console.log('No se tienen permisos suficientes para: ' + file)
	        process.exit(1) 
	      }
	      else {
	      	console.log('Error al leer: ' + file)
	        process.exit(1)
	      }
	    }
	    else {
	      let r = content.toString().split("\n")
	      parseRules(r)
	      // console.log(rules)
	      avoidDuplicate(rules)
	    }
	  })
	} 

	/**
	 * Valida la petición por una regla del WAF
	 * @param {string} info - contenido a analizar 
	 * @param {string} operator - si es iregex o regex
	 * @param {string} action - accion a tomar en caso de que la regla haga match
	 * @param {string} id - id de la regla
	 * @param {string} descripcion - descripcion de la regla
	 * @returns {object|boolean} - objeto con la accion a tomar en caso de hacer match, en caso 
	 * contrario se devuelve false
	 */
	const validateRule = (info, operator, regex, action, id, descripcion) => {
		let re
		if(operator === 'iregex') {
			re = new RegExp(regex, 'i')
		} else if(operator === 'regex') {
			re = new RegExp(regex)
		} else {
			console.log('Error en operador. Verifica que la sintaxis corresponda a "iregex" o "regex"')
			process.exit(1)
		}
		if(re.test(info)) {
			console.log("-> Se ha generado una alerta en audit.log")
			return {
				action: action,
				id: id,
				descripcion: descripcion
			}
		} else {
			return false
		}
	}

	/**
	 * Analiza una petición dada 
	 * @params {Array}	args - argumentos con los que se analizará la petición:
	 * AGENTE_USUARIO,
	 * METODO,
	 * RECURSO,
	 * CUERPO,
	 * CLIENTE_IP,
	 * CABECERAS_VALORES,
	 * CABECERAS_NOMBRES,
	 * CABECERAS,
	 * PETICION_LINEA,
	 * COOKIES,
	 * @returns {Array} actions - acciones que debe tomar el servidor en base al anaĺisis realizado
	 */
	this.analyzeRequest = (...args) => {
		let actions = [] 
		rules.forEach(r => {
			let vars = r.variables.split("|") //getting all variables
			vars.forEach(v => {
				let index = variableArgumento.indexOf(v)
				let infoToAnalyze = args[index]
				let action = validateRule(infoToAnalyze, r.operador, r.expresion, r.accion, r.regla, r.descripcion)
				if (action) actions.push(action)
			})
		})
		return actions
	}
}