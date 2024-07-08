const service = require("./service.js")

module.exports = async function (context, req) {

    context.log(`got request with query parameters: ${JSON.stringify(req.query)}`)

    if (Object.keys(req.query).length > 0) {
        if (req.query.resource === 'plugin.json') {
            context.res = {
                body: service.PLUGIN_JSON
            };
        } else if (req.query.resource === 'openapi.yaml') {
            context.res = {
                body: service.YAML
            };
        } else if (req.query.incidentId) {
            let incident = await service.getIncidentById(context, await service.getAzureAuthenticationToken(), req.query.incidentId)
            context.res = {
                body: incident
            }
        } else if (req.query.incidentNumber) {
            let incident = await service.getIncidentByNumber(context, await service.getAzureAuthenticationToken(), req.query.incidentNumber)
            context.res = {
                body: incident
            }
        }
    } else if (Object.keys(req.query).length === 0) {
        let incidents = await service.fetchIncidents(context, await service.getAzureAuthenticationToken(), [])
        context.res = {
            body: {total: incidents.length, incidents: incidents}
        };
    }
}
