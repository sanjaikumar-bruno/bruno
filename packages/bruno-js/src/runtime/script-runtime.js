const { NodeVM } = require('@usebruno/vm2');
const path = require('path');
const http = require('http');
const https = require('https');
const stream = require('stream');
const util = require('util');
const zlib = require('zlib');
const url = require('url');
const punycode = require('punycode');
const fs = require('fs');
const { get } = require('lodash');
const Bru = require('../bru');
const BrunoRequest = require('../bruno-request');
const BrunoResponse = require('../bruno-response');
const { cleanJson } = require('../utils');
const { createBruTestResultMethods } = require('../utils/results');

// Inbuilt Library Support
const ajv = require('ajv');
const addFormats = require('ajv-formats');
const atob = require('atob');
const btoa = require('btoa');
const lodash = require('lodash');
const moment = require('moment');
const uuid = require('uuid');
const nanoid = require('nanoid');
const axios = require('axios');
const fetch = require('node-fetch');
const chai = require('chai');
const CryptoJS = require('crypto-js');
const NodeVault = require('node-vault');
const xml2js = require('xml2js');
const cheerio = require('cheerio');
const tv4 = require('tv4');
const { executeQuickJsVmAsync } = require('../sandbox/quickjs');

class ScriptRuntime {
  constructor(props) {
    this.runtime = props?.runtime || 'vm2';
  }

  // This approach is getting out of hand
  // Need to refactor this to use a single arg (object) instead of 7
  async runRequestScript(
    script,
    request,
    envVariables,
    runtimeVariables,
    collectionPath,
    onConsoleLog,
    processEnvVars,
    scriptingConfig,
    runRequestByItemPathname,
    collectionName
  ) {
    const globalEnvironmentVariables = request?.globalEnvironmentVariables || {};
    const oauth2CredentialVariables = request?.oauth2CredentialVariables || {};
    const collectionVariables = request?.collectionVariables || {};
    const folderVariables = request?.folderVariables || {};
    const requestVariables = request?.requestVariables || {};
    const assertionResults = request?.assertionResults || [];
    const bru = new Bru(envVariables, runtimeVariables, processEnvVars, collectionPath, collectionVariables, folderVariables, requestVariables, globalEnvironmentVariables, oauth2CredentialVariables, collectionName);
    const req = new BrunoRequest(request);
    const allowScriptFilesystemAccess = get(scriptingConfig, 'filesystemAccess.allow', false);
    const moduleWhitelist = get(scriptingConfig, 'moduleWhitelist', []);
    const additionalContextRoots = get(scriptingConfig, 'additionalContextRoots', []);
    const additionalContextRootsAbsolute = lodash
      .chain(additionalContextRoots)
      .map((acr) => (acr.startsWith('/') ? acr : path.join(collectionPath, acr)))
      .value();

    const whitelistedModules = {};

    for (let module of moduleWhitelist) {
      try {
        whitelistedModules[module] = require(module);
      } catch (e) {
        // Ignore
        console.warn(e);
      }
    }

    // extend bru with result getter methods
    const { __brunoTestResults, test } = createBruTestResultMethods(bru, assertionResults, chai);

    const context = {
      bru,
      req,
      test,
      expect: chai.expect,
      assert: chai.assert,
      __brunoTestResults: __brunoTestResults
    };

    if (onConsoleLog && typeof onConsoleLog === 'function') {
      const customLogger = (type) => {
        return (...args) => {
          onConsoleLog(type, cleanJson(args));
        };
      };
      context.console = {
        log: customLogger('log'),
        debug: customLogger('debug'),
        info: customLogger('info'),
        warn: customLogger('warn'),
        error: customLogger('error')
      };
    }

    if (runRequestByItemPathname) {
      context.bru.runRequest = runRequestByItemPathname;
    }

    if (this.runtime === 'quickjs') {
      await executeQuickJsVmAsync({
        script: script,
        context: context,
        collectionPath
      });

      return {
        request,
        envVariables: cleanJson(envVariables),
        runtimeVariables: cleanJson(runtimeVariables),
        globalEnvironmentVariables: cleanJson(globalEnvironmentVariables),
        results: cleanJson(__brunoTestResults.getResults()),
        nextRequestName: bru.nextRequest,
        skipRequest: bru.skipRequest,
        stopExecution: bru.stopExecution
      };
    }

    // default runtime is vm2
    const vm = new NodeVM({
      sandbox: context,
      require: {
        context: 'sandbox',
        builtin: [ "*" ],
        external: true,
        root: [collectionPath, ...additionalContextRootsAbsolute],
        mock: {
          // node libs
          path,
          stream,
          util,
          url,
          http,
          https,
          punycode,
          zlib,
          // 3rd party libs
          ajv,
          'ajv-formats': addFormats,
          atob,
          btoa,
          lodash,
          moment,
          uuid,
          nanoid,
          axios,
          chai,
          'node-fetch': fetch,
          'crypto-js': CryptoJS,
          xml2js: xml2js,
          cheerio,
          tv4,
          ...whitelistedModules,
          fs: allowScriptFilesystemAccess ? fs : undefined,
          'node-vault': NodeVault
        }
      }
    });
    const asyncVM = vm.run(`module.exports = async () => { ${script} }`, path.join(collectionPath, 'vm.js'));
    await asyncVM();

    return {
      request,
      envVariables: cleanJson(envVariables),
      runtimeVariables: cleanJson(runtimeVariables),
      globalEnvironmentVariables: cleanJson(globalEnvironmentVariables),
      results: cleanJson(__brunoTestResults.getResults()),
      nextRequestName: bru.nextRequest,
      skipRequest: bru.skipRequest,
      stopExecution: bru.stopExecution
    };
  }

  async runResponseScript(
    script,
    request,
    response,
    envVariables,
    runtimeVariables,
    collectionPath,
    onConsoleLog,
    processEnvVars,
    scriptingConfig,
    runRequestByItemPathname,
    collectionName
  ) {
    const globalEnvironmentVariables = request?.globalEnvironmentVariables || {};
    const oauth2CredentialVariables = request?.oauth2CredentialVariables || {};
    const collectionVariables = request?.collectionVariables || {};
    const folderVariables = request?.folderVariables || {};
    const requestVariables = request?.requestVariables || {};
    const assertionResults = request?.assertionResults || [];
    const bru = new Bru(envVariables, runtimeVariables, processEnvVars, collectionPath, collectionVariables, folderVariables, requestVariables, globalEnvironmentVariables, oauth2CredentialVariables, collectionName);
    const req = new BrunoRequest(request);
    const res = new BrunoResponse(response);
    const allowScriptFilesystemAccess = get(scriptingConfig, 'filesystemAccess.allow', false);
    const moduleWhitelist = get(scriptingConfig, 'moduleWhitelist', []);
    const additionalContextRoots = get(scriptingConfig, 'additionalContextRoots', []);
    const additionalContextRootsAbsolute = lodash
      .chain(additionalContextRoots)
      .map((acr) => (acr.startsWith('/') ? acr : path.join(collectionPath, acr)))
      .value();

    const whitelistedModules = {};

    for (let module of moduleWhitelist) {
      try {
        whitelistedModules[module] = require(module);
      } catch (e) {
        // Ignore
        console.warn(e);
      }
    }

    // extend bru with result getter methods
    const { __brunoTestResults, test } = createBruTestResultMethods(bru, assertionResults, chai);

    const context = {
      bru,
      req,
      res,
      test,
      expect: chai.expect,
      assert: chai.assert,
      __brunoTestResults: __brunoTestResults
    };

    if (onConsoleLog && typeof onConsoleLog === 'function') {
      const customLogger = (type) => {
        return (...args) => {
          onConsoleLog(type, cleanJson(args));
        };
      };
      context.console = {
        log: customLogger('log'),
        info: customLogger('info'),
        warn: customLogger('warn'),
        error: customLogger('error'),
        debug: customLogger('debug')
      };
    }

    if (runRequestByItemPathname) {
      context.bru.runRequest = runRequestByItemPathname;
    }

    if (this.runtime === 'quickjs') {
      await executeQuickJsVmAsync({
        script: script,
        context: context,
        collectionPath
      });

      return {
        response,
        envVariables: cleanJson(envVariables),
        runtimeVariables: cleanJson(runtimeVariables),
        globalEnvironmentVariables: cleanJson(globalEnvironmentVariables),
        results: cleanJson(__brunoTestResults.getResults()),
        nextRequestName: bru.nextRequest,
        skipRequest: bru.skipRequest,
        stopExecution: bru.stopExecution
      };
    }

    // default runtime is vm2
    const vm = new NodeVM({
      sandbox: context,
      require: {
        context: 'sandbox',
        builtin: [ "*" ],
        external: true,
        root: [collectionPath, ...additionalContextRootsAbsolute],
        mock: {
          // node libs
          path,
          stream,
          util,
          url,
          http,
          https,
          punycode,
          zlib,
          // 3rd party libs
          ajv,
          'ajv-formats': addFormats,
          atob,
          btoa,
          lodash,
          moment,
          uuid,
          nanoid,
          axios,
          'node-fetch': fetch,
          'crypto-js': CryptoJS,
          'xml2js': xml2js,
          cheerio,
          tv4,
          ...whitelistedModules,
          fs: allowScriptFilesystemAccess ? fs : undefined,
          'node-vault': NodeVault
        }
      }
    });

    const asyncVM = vm.run(`module.exports = async () => { ${script} }`, path.join(collectionPath, 'vm.js'));
    await asyncVM();

    return {
      response,
      envVariables: cleanJson(envVariables),
      runtimeVariables: cleanJson(runtimeVariables),
      globalEnvironmentVariables: cleanJson(globalEnvironmentVariables),
      results: cleanJson(__brunoTestResults.getResults()),
      nextRequestName: bru.nextRequest,
      skipRequest: bru.skipRequest,
      stopExecution: bru.stopExecution
    };
  }
}

module.exports = ScriptRuntime;
