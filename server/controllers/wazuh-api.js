/*
 * Wazuh app - Class for Wazuh-API functions
 * Copyright (C) 2018 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

// Require some libraries
import needle               from 'needle';
import pciRequirementsFile  from '../integration-files/pci-requirements';
import gdprRequirementsFile from '../integration-files/gdpr-requirements';
import ElasticWrapper       from '../lib/elastic-wrapper';
import getPath              from '../../util/get-path';
import packageInfo          from '../../package.json';
import monitoring           from '../monitoring';
import ErrorResponse        from './error-response';
import { Parser }           from 'json2csv';
import getConfiguration     from '../lib/get-configuration';
import { totalmem }         from 'os';

export default class WazuhApi {
    constructor(server){
        this.wzWrapper = new ElasticWrapper(server);
        this.fetchAgentsExternal = monitoring(server,{disableCron:true})
    }

    async checkStoredAPI (req, reply) {
        try{

            // Get config from elasticsearch
            const wapi_config = await this.wzWrapper.getWazuhConfigurationById(req.payload)
            if (wapi_config.error_code > 1) {
                throw new Error(`Could not find Wazuh API entry on Elasticsearch.`)
            } else if (wapi_config.error_code > 0) {
                throw new Error('Valid credentials not found in Elasticsearch. It seems the credentials were not saved.')
            }

            let response = await needle('get', `${wapi_config.url}:${wapi_config.port}/version`, {}, {
                headers: {
                    'wazuh-app-version': packageInfo.version
                },
                username          : wapi_config.user,
                password          : wapi_config.password,
                rejectUnauthorized: !wapi_config.insecure
            })

            if (parseInt(response.body.error) === 0 && response.body.data) {
                // Checking the cluster status
                response = await needle('get', `${wapi_config.url}:${wapi_config.port}/cluster/status`, {}, {
                    headers: {
                        'wazuh-app-version': packageInfo.version
                    },
                    username          : wapi_config.user,
                    password          : wapi_config.password,
                    rejectUnauthorized: !wapi_config.insecure
                })

                if (!response.body.error) {
                    // If cluster mode is active
                    if (response.body.data.enabled === 'yes') {
                        response = await needle('get', `${wapi_config.url}:${wapi_config.port}/cluster/node`, {}, {
                            headers: {
                                'wazuh-app-version': packageInfo.version
                            },
                            username          : wapi_config.user,
                            password          : wapi_config.password,
                            rejectUnauthorized: !wapi_config.insecure
                        })

                        if (!response.body.error) {
                            let managerName = wapi_config.cluster_info.manager;
                            delete wapi_config.cluster_info;
                            wapi_config.cluster_info         = {};
                            wapi_config.cluster_info.status  = 'enabled';
                            wapi_config.cluster_info.manager = managerName;
                            wapi_config.cluster_info.node    = response.body.data.node;
                            wapi_config.cluster_info.cluster = response.body.data.cluster;
                            wapi_config.password = '****'
                            return reply({ statusCode: 200, data: wapi_config });

                        } else if (response.body.error){
                            const tmpMsg = response && response.body && response.body.message ?
                                           response.body.message :
                                           'Unexpected error from /cluster/node';

                            throw new Error(tmpMsg)
                        }

                    } else { // Cluster mode is not active
                        let managerName = wapi_config.cluster_info.manager;
                        delete wapi_config.cluster_info;
                        wapi_config.cluster_info         = {};
                        wapi_config.cluster_info.status  = 'disabled';
                        wapi_config.cluster_info.cluster = 'Disabled';
                        wapi_config.cluster_info.manager = managerName;
                        wapi_config.password = '****'

                        return reply({ statusCode: 200, data: wapi_config });
                    }

                } else {
                    const tmpMsg = response && response.body && response.body.message ?
                                   response.body.message :
                                   'Unexpected error from /cluster/status';

                    throw new Error(tmpMsg)
                }

            } else {
                throw new Error(`${wapi_config.url}:${wapi_config.port}/version is unreachable`)
            }
        } catch(error){
            if(error.code === 'ECONNREFUSED'){
                return reply({ statusCode: 200, data: {password: '****', apiIsDown: true } });
            } else {
                return ErrorResponse(error.message || error, 3002, 500, reply);
            }
        }
    }

    validateCheckApiParams (payload)  {
        if (!('user' in payload)) {
            return 'Missing param: API USER';
        }

        if (!('password' in payload) && !('id' in payload)) {
            return 'Missing param: API PASSWORD';
        }

        if (!('url' in payload)) {
            return 'Missing param: API URL';
        }

        if (!('port' in payload)) {
            return 'Missing param: API PORT';
        }

        if (!(payload.url.includes('https://')) && !(payload.url.includes('http://'))) {
            return 'protocol_error';
        }

        return false;
    }

    async checkAPI (req, reply) {
        try {
            
            let apiAvailable = null;
            
            const notValid = this.validateCheckApiParams(req.payload);
            if(notValid) return ErrorResponse(notValid, 3003, 500, reply);

            // Check if a Wazuh API id is given (already stored API)
            if(req.payload && req.payload.id && !req.payload.password) {

                const data = await this.wzWrapper.getWazuhConfigurationById(req.payload.id);
                if(data) apiAvailable = data;
                else return ErrorResponse(`The API ${req.payload.id} was not found`, 3029, 500, reply);

            // Check if a password is given
            } else if(req.payload && req.payload.password) {

                apiAvailable = req.payload;
                apiAvailable.password = Buffer.from(req.payload.password, 'base64').toString('ascii');
                
            } 

            let response = await needle('get', `${apiAvailable.url}:${apiAvailable.port}/version`, {}, {
                headers: {
                    'wazuh-app-version': packageInfo.version
                },
                username          : apiAvailable.user,
                password          : apiAvailable.password,
                rejectUnauthorized: !apiAvailable.insecure
            })


            // Check wrong credentials
            if(parseInt(response.statusCode) === 401){
                return ErrorResponse('Wrong credentials', 3004, 500, reply);
            }

            if (parseInt(response.body.error) === 0 && response.body.data) {

                response = await needle('get', `${apiAvailable.url}:${apiAvailable.port}/agents/000`, {}, {
                    headers: {
                        'wazuh-app-version': packageInfo.version
                    },
                    username          : apiAvailable.user,
                    password          : apiAvailable.password,
                    rejectUnauthorized: !apiAvailable.insecure
                })

                if (!response.body.error) {
                    const managerName = response.body.data.name;

                    response = await needle('get', `${apiAvailable.url}:${apiAvailable.port}/cluster/status`, {}, { // Checking the cluster status
                        headers: {
                            'wazuh-app-version': packageInfo.version
                        },
                        username          : apiAvailable.user,
                        password          : apiAvailable.password,
                        rejectUnauthorized: !apiAvailable.insecure
                    })

                    if (!response.body.error) {
                        if (response.body.data.enabled === 'yes') {

                            // If cluster mode is active
                            response = await needle('get', `${apiAvailable.url}:${apiAvailable.port}/cluster/node`, {}, {
                                headers: {
                                    'wazuh-app-version': packageInfo.version
                                },
                                username          : apiAvailable.user,
                                password          : apiAvailable.password,
                                rejectUnauthorized: !apiAvailable.insecure
                            })

                            if (!response.body.error) {
                                return reply({
                                    manager: managerName,
                                    node   :    response.body.data.node,
                                    cluster: response.body.data.cluster,
                                    status : 'enabled'
                                });
                            }

                        } else {

                            // Cluster mode is not active
                            return reply({
                                manager: managerName,
                                cluster: 'Disabled',
                                status : 'disabled'
                            });
                        }
                    }
                }
            }
            const tmpMsg = response.body && response.body.message ?
                           response.body.message :
                           'Unexpected error checking the Wazuh API';

            throw new Error(tmpMsg)

        } catch(error) {
            return ErrorResponse(error.message || error, 3005, 500, reply);
        }
    }

    async getPciRequirement (req, reply) {
        try {

            let pci_description = '';

            if (req.params.requirement === 'all') {
                if(!req.headers.id) {
                    return reply(pciRequirementsFile);
                }
                let wapi_config = await this.wzWrapper.getWazuhConfigurationById(req.headers.id);

                if (wapi_config.error_code > 1) {
                    // Can not connect to elasticsearch
                    return ErrorResponse('Elasticsearch unexpected error or cannot connect', 3007, 400, reply);
                } else if (wapi_config.error_code > 0) {
                    // Credentials not found
                    return ErrorResponse('Credentials does not exists', 3008, 400, reply);
                }

                const response = await needle('get', `${wapi_config.url}:${wapi_config.port}/rules/pci`, {}, {
                    headers: {
                        'wazuh-app-version': packageInfo.version
                    },
                    username          : wapi_config.user,
                    password          : wapi_config.password,
                    rejectUnauthorized: !wapi_config.insecure
                })

                if(response.body.data && response.body.data.items){
                    let PCIobject = {};
                    for(let item of response.body.data.items){
                        if(typeof pciRequirementsFile[item] !== 'undefined') PCIobject[item] = pciRequirementsFile[item];
                    }
                    return reply(PCIobject);
                } else {
                    return ErrorResponse('An error occurred trying to parse PCI DSS requirements', 3009, 400, reply);
                }

            } else {
                if (typeof pciRequirementsFile[req.params.requirement] !== 'undefined'){
                    pci_description = pciRequirementsFile[req.params.requirement];
                }

                return reply({
                    pci: {
                        requirement: req.params.requirement,
                        description: pci_description
                    }
                });
            }
        } catch (error) {
            return ErrorResponse(error.message || error, 3010, 400, reply);
        }

    }

    async getGdprRequirement (req, reply) {
        try {
            let gdpr_description = '';

            if (req.params.requirement === 'all') {
                if(!req.headers.id) {
                    return reply(gdprRequirementsFile);
                }
                const wapi_config = await this.wzWrapper.getWazuhConfigurationById(req.headers.id);
                
                // Checking for GDPR 
                const version = await needle('get', `${wapi_config.url}:${wapi_config.port}/version`, {}, {
                    headers: {
                        'wazuh-app-version': packageInfo.version
                    },
                    username          : wapi_config.user,
                    password          : wapi_config.password,
                    rejectUnauthorized: !wapi_config.insecure
                });
                
                const number = version.body.data;

                const major = number.split('v')[1].split('.')[0]
                const minor = number.split('v')[1].split('.')[1].split('.')[0]
                const patch = number.split('v')[1].split('.')[1].split('.')[1]

                if((major >= 3 && minor < 2) || (major >= 3 && minor >= 2 && patch < 3)){
                    return reply({});
                }

                if (wapi_config.error_code > 1) {
                    // Can not connect to elasticsearch
                    return ErrorResponse('Elasticsearch unexpected error or cannot connect', 3024, 400, reply);
                } else if (wapi_config.error_code > 0) {
                    // Credentials not found
                    return ErrorResponse('Credentials does not exists', 3025, 400, reply);
                }

                const response = await needle('get', `${wapi_config.url}:${wapi_config.port}/rules/gdpr`, {}, {
                    headers: {
                        'wazuh-app-version': packageInfo.version
                    },
                    username          : wapi_config.user,
                    password          : wapi_config.password,
                    rejectUnauthorized: !wapi_config.insecure
                })

                if(response.body.data && response.body.data.items){
                    let GDPRobject = {};
                    for(let item of response.body.data.items){
                        if(typeof gdprRequirementsFile[item] !== 'undefined') GDPRobject[item] = gdprRequirementsFile[item];
                    }
                    return reply(GDPRobject);
                } else {
                    return ErrorResponse('An error occurred trying to parse GDPR requirements', 3026, 400, reply);
                }

            } else {
                if (typeof gdprRequirementsFile[req.params.requirement] !== 'undefined'){
                    gdpr_description = gdprRequirementsFile[req.params.requirement];
                }

                return reply({
                    gdpr: {
                        requirement: req.params.requirement,
                        description: gdpr_description
                    }
                });
            }
        } catch (error) {
            return ErrorResponse(error.message || error, 3027, 400, reply);
        }

    }

    async makeRequest (method, path, data, id, reply) {
        try {
            const wapi_config = await this.wzWrapper.getWazuhConfigurationById(id);

            if (wapi_config.error_code > 1) {
                //Can not connect to elasticsearch
                return ErrorResponse('Could not connect with elasticsearch', 3011, 404, reply);
            } else if (wapi_config.error_code > 0) {
                //Credentials not found
                return ErrorResponse('Credentials does not exists', 3012, 404, reply);
            }

            if (!data) {
                data = {};
            }

            const options = {
                headers: {
                    'wazuh-app-version': packageInfo.version
                },
                username          : wapi_config.user,
                password          : wapi_config.password,
                rejectUnauthorized: !wapi_config.insecure
            };

            const fullUrl   = getPath(wapi_config) + path;
            const response  = await needle(method, fullUrl, data, options);

            if(response && response.body && !response.body.error && response.body.data) {
                return reply(response.body)
            }

            throw response && response.body && response.body.error && response.body.message ?
                  new Error(response.body.message) :
                  new Error('Unexpected error fetching data from the Wazuh API')

        } catch (error) {
            return ErrorResponse(error.message || error, 3013, 500, reply);
        }
    }

    requestApi (req, reply) {
        if (!req.payload.method) {
            return ErrorResponse('Missing param: method', 3015, 400, reply);
        } else if (!req.payload.path) {
            return ErrorResponse('Missing param: path', 3016, 400, reply);
        } else {
            if(req.payload.method !== 'GET' && req.payload.body && req.payload.body.devTools){
                const configuration = getConfiguration();
                if(!configuration || (configuration && !configuration['devtools.allowall'])){
                    return ErrorResponse('Allowed method: [GET]', 3029, 400, reply);
                }
            }
            if(req.payload.body.devTools) {
                delete req.payload.body.devTools;
                const keyRegex = new RegExp(/.*agents\/\d*\/key.*/)
                if(typeof req.payload.path === 'string' &&  keyRegex.test(req.payload.path)){
                    return ErrorResponse('Forbidden route /agents/<id>/key', 3028, 400, reply);
                }
            }
            return this.makeRequest(req.payload.method, req.payload.path, req.payload.body, req.payload.id, reply);
        }
    }

    // Fetch agent status and insert it directly on demand
    async fetchAgents (req, reply) {
        try{
            const output = await this.fetchAgentsExternal();
            return reply({
                'statusCode': 200,
                'error':      '0',
                'data':       '',
                output
            });
        } catch(error){
            return ErrorResponse(error.message || error, 3018, 500, reply);
        }
    }

    getConfigurationFile (req,reply) {
        try{
            const configFile = getConfiguration();

            return reply({
                statusCode: 200,
                error     : 0,
                data      : configFile || {}
            });

        } catch (error) {
            return ErrorResponse(error.message || error, 3019, 500, reply);
        }
    }

    /**
     * Get full data on CSV format from a list Wazuh API endpoint
     * @param {*} req
     * @param {*} res
     */
    async csv(req,reply) {
        try{

            if(!req.payload || !req.payload.path) throw new Error('Field path is required')
            if(!req.payload.id) throw new Error('Field id is required')

            const filters = req.payload && req.payload.filters && Array.isArray(req.payload.filters) ?
                            req.payload.filters :
                            [];

            const config = await this.wzWrapper.getWazuhConfigurationById(req.payload.id)

            let path_tmp = req.payload.path;

            if(path_tmp && typeof path_tmp === 'string'){
                path_tmp = path_tmp[0] === '/' ? path_tmp.substr(1) : path_tmp
            }

            if(!path_tmp) throw new Error('An error occurred parsing path field')

            // Real limit, regardless the user query
            const params = { limit: 45000 };

            if(filters.length) {
                for(const filter of filters) {
                    if(!filter.name || !filter.value) continue;
                    params[filter.name] = filter.value;
                }
            }

            const output = await needle('get', `${config.url}:${config.port}/${path_tmp}`, params, {
                headers: {
                    'wazuh-app-version': packageInfo.version
                },
                username          : config.user,
                password          : config.password,
                rejectUnauthorized: !config.insecure
            })

            if(output && output.body && output.body.data && output.body.data.totalItems) {
                const fields = Object.keys(output.body.data.items[0]);
                const data   = output.body.data.items;

                const json2csvParser = new Parser({ fields });
                const csv            = json2csvParser.parse(data);

                return reply(csv).type('text/csv')

            } else if (output && output.body && output.body.data && !output.body.data.totalItems) {

                throw new Error('No results')

            } else {

                throw new Error('An error occurred fetching data from the Wazuh API')

            }

        } catch (error) {
            return ErrorResponse(error.message || error, 3034, 500, reply);
        }
    }

    

    async totalRam(req,reply) {
        try{
            // RAM in MB
            const ram = Math.ceil(totalmem()/1024/1024);
            return reply({ statusCode: 200, error: 0, ram });
        } catch (error) {
            return ErrorResponse(error.message || error, 3033, 500, reply);
        }
    }


    async getAgentsFieldsUniqueCount(req, reply) {
        try {

            if(!req.params || !req.params.api) throw new Error('Field api is required')

            const config  = await this.wzWrapper.getWazuhConfigurationById(req.params.api);
            
            const headers = {
                headers: {
                    'wazuh-app-version': packageInfo.version
                },
                username          : config.user,
                password          : config.password,
                rejectUnauthorized: !config.insecure
            };
            
            const url = `${config.url}:${config.port}/agents`;

            const params = {
                limit : 500,
                offset: 0,
                sort  :'-date_add'
            }
            
            const items = [];

            const output = await needle('get', url, params, headers)
            
            items.push(...output.body.data.items)

            const totalItems = output.body.data.totalItems;

            /*
            while(items.length < totalItems){
                params.offset += params.limit;
                const tmp = await needle('get', url, params, headers)
                items.push(...tmp.body.data.items)
            }
            */
            
            const result = {
                groups     : [],
                nodes      : [],
                versions   : [],
                osPlatforms: [],
                lastAgent  : items[0],
                summary: {
                    agentsCountActive        :0,
                    agentsCountDisconnected  :0,
                    agentsCountNeverConnected:0,
                    agentsCountTotal         :0,
                    agentsCoverity           :0
                }
            }

            /*
            for(const agent of items){
                if(agent.id === '000') continue;
                if(agent.group && !result.groups.includes(agent.group)) result.groups.push(agent.group);
                if(agent.node_name && !result.nodes.includes(agent.node_name)) result.nodes.push(agent.node_name);
                if(agent.version && !result.versions.includes(agent.version)) result.versions.push(agent.version);
                if(agent.os && agent.os.name){
                    const exists = result.osPlatforms.filter((e) => e.name === agent.os.name && e.platform === agent.os.platform && e.version === agent.os.version);
                    if(!exists.length){
                        result.osPlatforms.push({
                            name:     agent.os.name,
                            platform: agent.os.platform,
                            version:  agent.os.version
                        });
                    }
                }
            }
            */

            if (config.cluster_info.cluster === "aws") {
                result.groups.push("default");

                result.nodes.push("node01");
                result.nodes.push("node02");
                result.nodes.push("node03");
                result.nodes.push("node04");

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Datacenter",
                    platform: "windows",
                    version:  "10.0.14393"
                });

                result.osPlatforms.push({
                    name:     "CentOS Linux",
                    platform: "centos",
                    version:  "7"
                });

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Datacenter",
                    platform: "windows",
                    version:  "10.0.14393"
                });

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2012 R2 Standard",
                    platform: "windows",
                    version:  "6.3.9600"
                });

                result.osPlatforms.push({
                    name:     "Ubuntu",
                    platform: "ubuntu",
                    version:  "16.04.4 LTS"
                });

                result.versions.push("Wazuh v2.0");
                result.versions.push("Wazuh v2.0.1");
                result.versions.push("Wazuh v2.1.1");

            } else if (config.cluster_info.cluster === "azure") {
                result.groups.push("default");

                result.nodes.push("node01");
                result.nodes.push("node02");
                result.nodes.push("node03");

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Datacenter",
                    platform: "windows",
                    version:  "10.0.14393"
                });

                result.osPlatforms.push({
                    name:     "Ubuntu",
                    platform: "ubuntu",
                    version:  "16.04.4 LTS"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "7.4"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "7.5"
                });

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2012 R2 Standard",
                    platform: "windows",
                    version:  "6.3.9600"
                });

                result.osPlatforms.push({
                    name:     "CentOS Linux",
                    platform: "centos",
                    version:  "7"
                });

                result.osPlatforms.push({
                    name:     "Microsoft Windows 10 Pro",
                    platform: "windows",
                    version:  "10.0.17134"
                });


                result.versions.push("Wazuh v2.0");
                result.versions.push("Wazuh v2.0.1");
                result.versions.push("Wazuh v2.1.1");
                result.versions.push("Wazuh v2.1.1 [Ver: 10.0.14393] - Wazuh v2.1.1");
                result.versions.push("Wazuh v3.2.1");

            } else if (config.cluster_info.cluster === "noncloud") {
                result.groups.push("default");
         
                result.nodes.push("node01");
                result.nodes.push("node02");
                result.nodes.push("node03");      
                result.nodes.push("node04");      
                result.nodes.push("node05");      
                result.nodes.push("node06");      
                result.nodes.push("node07");      
                result.nodes.push("node08");      

                result.versions.push('Wazuh v2.1.0');
                result.versions.push('Wazuh v2.1.1');
                result.versions.push('Wazuh v2.1.1 [Ver: 6.2.9200] - Wazuh v2.1.1');
                result.versions.push('Wazuh v2.0.1');
                result.versions.push('Wazuh v3.2.1 [Ver: 6.2.9200] - Wazuh v3.2.1');
                result.versions.push('Wazuh v2.1.1 [Ver: 6.3.9600] - Wazuh v2.1.1');
                result.versions.push('Wazuh v2.1.1 [Ver: 10.0.14393] - Wazuh v2.1.1');
                result.versions.push('Wazuh v3.2.1');
                result.versions.push('Wazuh v3.2.2');
                result.versions.push('Wazuh v3.2.1 [Ver: 6.3.9600] - Wazuh v3.2.1');

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Datacenter",
                    platform: "windows",
                    version:  "10.0.14393"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "6.5"
                });

                result.osPlatforms.push({
                    name:     "KDE neon",
                    platform: "neon",
                    version:  "5.12"
                });

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Datacenter",
                    platform: "windows",
                    version:  "10.0.14393"
                });

                result.osPlatforms.push({
                    name:     "Ubuntu",
                    platform: "ubuntu",
                    version:  "16.04.1 LTS"
                }); 

                result.osPlatforms.push({
                    name:     "Microsoft Windows Server 2016 Standard",
                    platform: "windows",
                    version:  "10.0.14393"
                });  

                result.osPlatforms.push({
                    name:     "CentOS Linux",
                    platform: "centos",
                    version:  "6.8"
                });  

                result.osPlatforms.push({
                    name:     "Ubuntu",
                    platform: "ubuntu",
                    version:  "16.04.4 LTS"
                }); 

                result.osPlatforms.push({
                    name:     "CentOS Linux",
                    platform: "centos",
                    version:  "7"
                });  

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "6.2"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "7.4"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "5.7"
                });

                result.osPlatforms.push({
                    name:     "Red Hat Enterprise Linux Server",
                    platform: "rhel",
                    version:  "6.5"
                });

                result.osPlatforms.push({"platform": "ubuntu", "version": "16.04.2 LTS", "name": "Ubuntu"});
                result.osPlatforms.push({"platform": "ubuntu", "version": "14.04.5 LTS, Trusty Tahr", "name": "Ubuntu"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows 7 Professional Service Pack 1"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.9", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows Server 2012 R2 Essentials"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.7", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows 8.1 Pro"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.15063", "name": "Microsoft Windows 10 Enterprise"});
                result.osPlatforms.push({"platform": "rhel", "version": "7.5", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows Server 2008 R2 Enterprise Edition (full) Service Pack 1"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.10", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows Storage Server 2012 R2 Standard"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows Server 2012 R2 Datacenter"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows 7 Enterprise Edition Professional Service Pack 1"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows 8.1 Pro with Media Center"});
                result.osPlatforms.push({"platform": "sles_sap", "version": "12-SP1", "name": "SLES_SAP"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.11", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.14393", "name": "Microsoft Windows Server 2016 Standard Evaluation"});
                result.osPlatforms.push({"platform": "windows", "version": "6.2.9200", "name": "Microsoft Windows Server 2012 StandardMicrosoft Windows Server 2012 Standard"});
                result.osPlatforms.push({"platform": "windows", "version": "6.0.6002", "name": "Microsoft Windows Server 2008 Standard Edition Service Pack 2"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.14393", "name": "Microsoft Windows Storage Server 2016 Standard"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.3", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.14393", "name": "Microsoft Windows Server 2016 StandardMicrosoft Windows Server 2016 Standard"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.16299", "name": "Microsoft Windows 10 Home"});
                result.osPlatforms.push({"platform": "ol", "version": "6.9", "name": "Oracle Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "desc", "name": "Microsoft Windows unknown version "});
                result.osPlatforms.push({"platform": "rhel", "version": "7.1", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "debian", "version": "7", "name": "Debian GNU/Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7600", "name": "Microsoft Windows Server 2008 R2 Standard Edition "});
                result.osPlatforms.push({"platform": "windows", "version": "5.2.3790", "name": "Microsoft Windows Server 2003, Enterprise Edition Service Pack 2"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows Server 2008 R2 Standard Edition Service Pack 1"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.8", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.4", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "centos", "version": "5.11", "name": "CentOS Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows 7 Home Premium Edition Home Edition Service Pack 1"});
                result.osPlatforms.push({"platform": "windows", "version": "5.2.3790", "name": "Microsoft Windows Server 2003 R2 Standard Edition Service Pack 2"});
                result.osPlatforms.push({"platform": "ol", "version": "6.8", "name": "Oracle Linux Server"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.6", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.16299", "name": "Microsoft Windows 10 Enterprise"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.15063", "name": "Microsoft Windows 10 Pro"});
                result.osPlatforms.push({"platform": "ubuntu", "version": "18.04 LTS", "name": "Ubuntu"});
                result.osPlatforms.push({"platform": "windows", "version": "5.1.2600", "name": "Microsoft Windows XP Professional Service Pack 3"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows 7 Ultimate Edition Professional Service Pack 1"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.16299", "name": "Microsoft Windows 10 Pro"});
                result.osPlatforms.push({"platform": "rhel", "version": "7.2", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "6.0.6002", "name": "Microsoft Windows Server 2008 Enterprise Edition (full) Service Pack 2"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.7", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "centos", "version": "6.9", "name": "CentOS Linux"});
                result.osPlatforms.push({"platform": "sles", "version": "12-SP1", "name": "SLES"});
                result.osPlatforms.push({"platform": "windows", "version": "6.3.9600", "name": "Microsoft Windows Server 2012 R2 Standard"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.4", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "centos", "version": "6.5", "name": "CentOS Linux"});
                result.osPlatforms.push({"platform": "hpux", "version": "11.31", "name": "HP-UX"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.7", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "centos", "version": "6.7", "name": "CentOS Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "6.2.9200", "name": "Microsoft Windows Storage Server 2012 Standard"});
                result.osPlatforms.push({"platform": "windows", "version": "6.2.9200", "name": "Microsoft Windows Server 2012 Datacenter"});
                result.osPlatforms.push({"platform": "windows", "version": "6.1.7601", "name": "Microsoft Windows Server 2008 R2 Datacenter Edition (full) Service Pack 1"});
                result.osPlatforms.push({"platform": "windows", "version": "6.2.9200", "name": "Microsoft Windows Server 2012 Standard"});
                result.osPlatforms.push({"platform": "ubuntu", "version": "14.04.4 LTS, Trusty Tahr", "name": "Ubuntu"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.9", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "rhel", "version": "7.3", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.10586", "name": "Microsoft Windows Server 2016 Technical Preview 4"});
                result.osPlatforms.push({"platform": "ubuntu", "version": "16.04.3 LTS", "name": "Ubuntu"});
                result.osPlatforms.push({"platform": "windows", "version": "5.2.3790", "name": "Microsoft Windows Server 2003, Standard Edition Service Pack 2"});
                result.osPlatforms.push({"platform": "rhel", "version": "5.5", "name": "Red Hat Enterprise Linux Server"});
                result.osPlatforms.push({"platform": "rhel", "version": "6.9", "name": "Red Hat Enterprise Linux"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.14393", "name": "Microsoft Windows 10 Pro"});
                result.osPlatforms.push({"platform": "windows", "version": "10.0.17134", "name": "Microsoft Windows 10 Pro"});


            }

            const summary = await needle('get', url + '/summary', {}, headers)

            // Once Wazuh core fixes agent 000 issues, this should be adjusted
            const active = summary.body.data.Active - 1;
            const total  = summary.body.data.Total - 1;

            result.summary.agentsCountActive         = active;
            result.summary.agentsCountDisconnected   = summary.body.data.Disconnected;
            result.summary.agentsCountNeverConnected = summary.body.data['Never connected'];
            result.summary.agentsCountTotal          = total;
            result.summary.agentsCoverity            = (active / total) * 100;
            
            return reply({error:0, result})

        } catch (error) {
            return ErrorResponse(error.message || error, 3035, 500, reply)
        }
    }

}

