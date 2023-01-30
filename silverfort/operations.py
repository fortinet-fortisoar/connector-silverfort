""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, jwt, time
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('silverfort')


class Silverfort:
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/')
        else:
            self.server_url = 'https://{0}'.format(self.server_url)
        self.user_id = config.get('user_id')
        self.user_secret = config.get('user_secret')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint, method='GET', params=None, data=None, json=None):
        token = self.get_jwt()
        url = '{0}{1}{2}'.format(self.server_url, '/v1/public/', endpoint)
        logger.info('Request URL {0}'.format(url))
        headers = {'Authorization': 'Bearer {0}'.format(token)}
        try:
            response = requests.request(method=method, url=url,
                                        params=params, headers=headers, data=data, json=json, verify=self.verify_ssl)
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            elif response.status_code == 404:
                return response
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))

    def get_jwt(self):
        return jwt.encode({"issuer": self.user_id, "iat": time.time()}, self.user_secret, algorithm='HS256')

    def get_user_principal_name(self, params):
        payload = {'domain': params.get('domain')}
        if params.get('email'):
            payload['email'] = params.get('email')
        else:
            payload['sam_account'] = params.get('sam_account')
        response = self.make_api_call('getUPN', params=payload)
        return response.get('user_principal_name')


def build_json(params):
    risk_name = params.get('risk_name')
    severity = params.get('severity')
    valid_for = params.get('valid_for')
    description = params.get('description')
    return {risk_name: {"severity": severity, "valid_for": valid_for, "description": description}}


def get_user_risk(config, params):
    sf = Silverfort(config)
    user_identification = params.get('user_identification')
    if user_identification == 'User Principal Name':
        payload = {'user_principal_name': params.get('upn')}
    else:
        payload = {'user_principal_name': sf.get_user_principal_name(params)}
    response = sf.make_api_call('getEntityRisk', params=payload)
    return response


def get_resource_risk(config, params):
    sf = Silverfort(config)
    resource_name = params.get('resource_name')
    domain = params.get('domain')
    payload = {'resource_name': resource_name, 'domain_name': domain}
    response = sf.make_api_call('getEntityRisk', params=payload)
    return response


def update_user_risk(config, params):
    sf = Silverfort(config)
    user_identification = params.get('user_identification')
    if user_identification == 'User Principal Name':
        upn = params.get('upn')
    else:
        upn = sf.get_user_principal_name(params)
    json = build_json(params)
    payload = {'user_principal_name': upn, 'risks': json}
    response = sf.make_api_call('updateEntityRisk', method='POST', json=payload)
    return response


def update_resource_risk(config, params):
    sf = Silverfort(config)
    resource_name = params.get('resource_name')
    domain = params.get('domain')
    json = build_json(params)
    payload = {'resource_name': resource_name, 'domain_name': domain, 'risks': json},
    response = sf.make_api_call('updateEntityRisk', method='POST', json=payload)
    return response


def check_health(config):
    try:
        sf = Silverfort(config)
        response = sf.make_api_call('getBootStatus')
        if response["status"] == "Active" or response["status"] == "Standby":
            return True
    except Exception as Err:
        logger.exception('Error occurred while connecting server: {0}'.format(str(Err)))
        raise ConnectorError('Error occurred while connecting server: {0}'.format(Err))


operations = {
    'get_user_risk': get_user_risk,
    'get_resource_risk': get_resource_risk,
    'update_user_risk': update_user_risk,
    'update_resource_risk': update_resource_risk
}
