const https = require('https');
const parser = require('node-html-parser');

const SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID
const RESOURCE_GROUP_NAME = process.env.AZURE_RESOURCE_GROUP_NAME
const WORKSPACE_ID = process.env.AZURE_WORKSPACE_ID
const CLIENT_ID = process.env.AZURE_CLIENT_ID
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET
const TENANT_ID = process.env.AZURE_TENANT_ID

const MAX_PROPERTY_LENGTH = 350

const PLUGIN_JSON = {
    schema_version: "v1",
    name_for_model: "synackhelperforsecuritycopilot",
    description_for_model: "Plugin for finding, describing and summarizing Synack incidents in Sentinel. Use it whenever a user asks about Synack incidents in Sentinel.",
    name_for_human: "Synack Helper for Security Copilot",
    description_for_human: "Find Synack incidents",
    api: {
        "type": "openapi",
        "url": "https://synack-helper-for-copilot.azurewebsites.net/api/copilot?resource=openapi.yaml",
        "is_user_authenticated": false
    },
    auth: {
        "type": "none"
    },
    // logo_url: "https://<your-domain>/logo.png",
    contact_email: "akozynets@synack.com",
    legal_info_url: "https://synack.com/"
}
const YAML = '' +
    'openapi: 3.0.1\n' +
    'info:\n' +
    '  title: Synack incidents API\n' +
    '  description: Find Synack incidents\n' +
    '  version: 0.1.0\n' +
    'servers:\n' +
    '  - url: https://synack-helper-for-copilot.azurewebsites.net/api/\n' +
    'paths:\n' +
    '  /copilot:\n' +
    '    get:\n' +
    '      operationId: getIncidents\n' +
    '      summary: Get a list of Synack Incidents\n' +
    '      description: Returns a list of Synack incidents\n' +
    '      parameters:\n' +
    '        - name: incidentId\n' +
    '          in: query\n' +
    '          description: Id of the incident to return\n' +
    '          required: false\n' +
    '          schema:\n' +
    '            type: string\n' +
    '        - name: incidentNumber\n' +
    '          in: query\n' +
    '          description: Incident number of the incident to return\n' +
    '          required: false\n' +
    '          schema:\n' +
    '            type: integer\n' +
    '      responses:\n' +
    '        \'200\':\n' +
    '          description: OK - Returns a list of Synack incidents or vulnerabilities\n' +
    '          content:\n' +
    '            application/json:\n' +
    '              schema:\n' +
    '                type: array\n' +
    '                items:\n' +
    '                  $ref: \'#/components/schemas/Incident\'\n' +
    'components:\n' +
    '  schemas:\n' +
    '    Incident:\n' +
    '      type: object\n' +
    '      properties:\n' +
    '        title:\n' +
    '          type: string\n' +
    '          description: The title of the Synack incident\n' +
    '        category:\n' +
    '          type: string\n' +
    '          description: The category of the Synack incident\n' +
    '        description:\n' +
    '          type: string\n' +
    '          description: The description of the Synack incident\n' +
    '        impact:\n' +
    '          type: string\n' +
    '          description: The impact of the Synack incident\n' +
    '        recommended_fix:\n' +
    '          type: string\n' +
    '          description: Recommended fix for the Synack incident\n' +
    '        assessment:\n' +
    '          type: string\n' +
    '          description: The assessment tp which the Synack incident belongs\n' +
    '        synack_link:\n' +
    '          type: string\n' +
    '          description: Url to the original vulnerability in Synack\n' +
    '        status:\n' +
    '          type: string\n' +
    '          description: Status of the Synack incident\n' +
    '        cvss:\n' +
    '          type: integer\n' +
    '          description: CVSS score of the Synack incident\n'

async function fetchIncidents(context, accessToken, incidents, nextLink) {
    return new Promise(((resolve, reject) => {
        let path = nextLink == null ? `/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_ID}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01`
            : nextLink
        let options = {
            hostname: 'management.azure.com',
            path: path,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + accessToken,
                'Content-Type': 'application/json'
            },
        }

        let request = https.request(options, function (response) {
            let responseContent = ''
            response.on('data', function (chunk) {
                responseContent += chunk
            })
            response.on('error', function (error) {
                context.log.error(`ERROR: ${error}`)
                reject(error)
            })
            response.on('end', function () {
                let statusCode = response.statusCode
                if (statusCode === 200) {
                    let responseJson = JSON.parse(responseContent)
                    let sentinelIncidentJson = responseJson['value']
                    for (let i = 0; i < sentinelIncidentJson.length; i++) {
                        let descriptionAsHtml = parser.parse(sentinelIncidentJson[i]['properties']['description'])
                        let dataHolders = descriptionAsHtml.querySelectorAll("span.synack-data")
                        for (const dataHolder of dataHolders) {
                            if (dataHolder.text) {
                                let value = dataHolder.text.length >= MAX_PROPERTY_LENGTH ? `${dataHolder.text.substring(0, MAX_PROPERTY_LENGTH - 5)}...` : dataHolder.text
                                sentinelIncidentJson[i]['properties'][dataHolder.getAttribute('name')] = value
                            }
                        }
                        incidents.push(sentinelIncidentJson[i])
                    }
                    if (responseJson['nextLink'] != null) {
                        fetchIncidents(context, accessToken, incidents, responseJson['nextLink'])
                            .then((incidents) => resolve(incidents))
                    } else {
                        resolve(incidents)
                    }
                } else {
                    context.log.error(`ERROR: could not get incidents`)
                    reject(responseContent)
                }
            })
        })
        request.end()
    }))
}

async function getIncidentById(context, accessToken, incidentId) {
    return new Promise(((resolve, reject) => {
        let path = `/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_ID}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2024-03-01`
        let options = {
            hostname: 'management.azure.com',
            path: path,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + accessToken,
                'Content-Type': 'application/json'
            },
        }

        let request = https.request(options, function (response) {
            let responseContent = ''
            response.on('data', function (chunk) {
                responseContent += chunk
            })
            response.on('error', function (error) {
                context.log.error(`ERROR: ${error}`)
                reject(error)
            })
            response.on('end', function () {
                let statusCode = response.statusCode
                if (statusCode === 200) {
                    context.log(`Got incident by id ${incidentId}`)
                    let sentinelIncidentJson = JSON.parse(responseContent)
                    let synackSentinelIncident = transformSentinelIncidentToSynackSentinelIncident(sentinelIncidentJson)
                    resolve(synackSentinelIncident)
                } else {
                    context.log.error(`ERROR: could not get incident with id ${incidentId}`)
                    reject(responseContent)
                }
            })
        })
        request.end()
    }))
}

function transformSentinelIncidentToSynackSentinelIncident(incident) {
    let descriptionAsHtml = parser.parse(incident['properties']['description'])
    let dataHolders = descriptionAsHtml.querySelectorAll("span.synack-data")
    for (const dataHolder of dataHolders) {
        if (dataHolder.text) {
            incident['properties'][dataHolder.getAttribute('name')] = dataHolder.text
        }
    }
    return incident
}

async function getIncidentByNumber(context, accessToken, incidentNumber, nextLink) {
    return new Promise(((resolve, reject) => {
        let path = nextLink == null ? `/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_ID}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01`
            : nextLink
        let options = {
            hostname: 'management.azure.com',
            path: path,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + accessToken,
                'Content-Type': 'application/json'
            },
        }

        let request = https.request(options, function (response) {
            let responseContent = ''
            response.on('data', function (chunk) {
                responseContent += chunk
            })
            response.on('error', function (error) {
                context.log.error(`ERROR: ${error}`)
                reject(error)
            })
            response.on('end', function () {
                let statusCode = response.statusCode
                incidentNumber = parseInt(incidentNumber)
                if (statusCode === 200) {
                    let responseJson = JSON.parse(responseContent)
                    let sentinelIncidentJson = responseJson['value']
                    let incident = null
                    for (let i = 0; i < sentinelIncidentJson.length; i++) {
                        let thisIncidentNumber = sentinelIncidentJson[i]['properties']['incidentNumber']
                        if (thisIncidentNumber === incidentNumber) {
                            context.log(`Found incident ${incidentNumber}.`)
                            incident = transformSentinelIncidentToSynackSentinelIncident(sentinelIncidentJson[i])
                            break
                        }
                    }
                    if (incident) {
                        resolve(incident)
                    } else {
                        if (responseJson['nextLink'] != null) {
                            context.log(`Incident with number ${incidentNumber} not found on this page. Getting next page of incidents.`)
                            getIncidentByNumber(context, accessToken, incidentNumber, responseJson['nextLink'])
                                .then((incident) => resolve(incident))
                        } else {
                            let message = `ERROR: could not get incident by number ${incidentNumber}`;
                            context.log.error(message)
                            reject(responseContent)
                        }
                    }
                } else {
                    context.log.error(`ERROR: could not get incident by number ${incidentNumber}`)
                    reject(responseContent)
                }
            })
        })
        request.end()
    }))
}


async function getAzureAuthenticationToken() {

    let secretForLog = CLIENT_SECRET == null ? '' : CLIENT_SECRET.replace(/./g, '*')
    console.log(`trying to get access token for: \n >>Subscription ID: ${SUBSCRIPTION_ID}\n >>Resource Group: ${RESOURCE_GROUP_NAME}\n >>Application (client) ID: ${CLIENT_ID}\n >>Client Secret\: ${secretForLog}\n`)

    return new Promise(((resolve, reject) => {
        let requestBody = `grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&resource=https://management.azure.com/`
        let options = {
            hostname: 'login.microsoftonline.com',
            path: `/${TENANT_ID}/oauth2/token`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': requestBody.length
            },
        }

        let request = https.request(options, function (response) {
                let responseContent = ''
                response.on('data', function (chunk) {
                    responseContent += chunk
                })
                response.on('error', function (error) {
                    context.log.error(`ERROR: ${error}`)
                })
                response.on('end', function () {
                    let responseJson = JSON.parse(responseContent)
                    if (response.statusCode === 200) {
                        resolve(responseJson.access_token)
                    } else {
                        context.log.error(`ERROR: failed to get access token`)
                        reject(responseContent)
                    }
                })
            }
        )
        request.write(requestBody)
        request.end()
    }))
}

exports.getAzureAuthenticationToken = getAzureAuthenticationToken
exports.fetchIncidents = fetchIncidents
exports.getIncidentById = getIncidentById
exports.getIncidentByNumber = getIncidentByNumber
exports.PLUGIN_JSON = PLUGIN_JSON
exports.YAML = YAML
