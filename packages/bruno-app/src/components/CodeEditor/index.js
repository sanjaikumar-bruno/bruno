/**
 *  Copyright (c) 2021 GraphQL Contributors.
 *
 *  This source code is licensed under the MIT license found in the
 *  LICENSE file in the root directory of this source tree.
 */

import React from 'react';
import { isEqual, escapeRegExp } from 'lodash';
import { defineCodeMirrorBrunoVariablesMode } from 'utils/common/codemirror';
import StyledWrapper from './StyledWrapper';
import * as jsonlint from '@prantlf/jsonlint';
import { JSHINT } from 'jshint';
import stripJsonComments from 'strip-json-comments';
import { getAllVariables } from 'utils/collections';

let CodeMirror;
const SERVER_RENDERED = typeof window === 'undefined' || global['PREVENT_CODEMIRROR_RENDER'] === true;
const TAB_SIZE = 2;

if (!SERVER_RENDERED) {
  CodeMirror = require('codemirror');
  window.jsonlint = jsonlint;
  window.JSHINT = JSHINT;
  //This should be done dynamically if possible
  const hintWords = [
    'res',
    'res.status',
    'res.statusText',
    'res.headers',
    'res.body',
    'res.responseTime',
    'res.getStatus()',
    'res.getHeader(name)',
    'res.getHeaders()',
    'res.getBody()',
    'res.getResponseTime()',
    'req',
    'req.url',
    'req.method',
    'req.headers',
    'req.body',
    'req.timeout',
    'req.getUrl()',
    'req.setUrl(url)',
    'req.getMethod()',
    'req.getAuthMode()',
    'req.setMethod(method)',
    'req.getHeader(name)',
    'req.getHeaders()',
    'req.setHeader(name, value)',
    'req.setHeaders(data)',
    'req.getBody()',
    'req.setBody(data)',
    'req.setMaxRedirects(maxRedirects)',
    'req.getTimeout()',
    'req.setTimeout(timeout)',
    'req.getExecutionMode()',
    'bru',
    'bru.cwd()',
    'bru.getEnvName()',
    'bru.getProcessEnv(key)',
    'bru.hasEnvVar(key)',
    'bru.getEnvVar(key)',
    'bru.getFolderVar(key)',
    'bru.getCollectionVar(key)',
    'bru.setEnvVar(key,value)',
    'bru.deleteEnvVar(key)',
    'bru.hasVar(key)',
    'bru.getVar(key)',
    'bru.setVar(key,value)',
    'bru.deleteVar(key)',
    'bru.deleteAllVars()',
    'bru.setNextRequest(requestName)',
    'req.disableParsingResponseJson()',
    'bru.getRequestVar(key)',
    'bru.runRequest(requestPathName)',
    'bru.getAssertionResults()',
    'bru.getTestResults()',
    'bru.sleep(ms)',
    'bru.getGlobalEnvVar(key)',
    'bru.setGlobalEnvVar(key, value)',
    'bru.runner',
    'bru.runner.setNextRequest(requestName)',
    'bru.runner.skipRequest()',
    'bru.runner.stopExecution()'
  ];
  
  // Add custom autocomplete functionality for 
  CodeMirror.registerHelper('hint', 'brunoJS', (editor) => {
    const cursor = editor.getCursor();
    const currentLine = editor.getLine(cursor.line);
    
    // Determine the range for the current word being typed (JavaScript)
    let start = cursor.ch;
    let end = start;
    while (end < currentLine.length && /[\w]/.test(currentLine.charAt(end))) ++end;
    while (start && /[\w]/.test(currentLine.charAt(start - 1))) --start;
    
    // Determine the range for the current word being typed (bru related)
    let startBru = cursor.ch;
    let endBru = startBru;
    while (endBru < currentLine.length && /[\w.]/.test(currentLine.charAt(endBru))) ++endBru;
    while (startBru && /[\w.]/.test(currentLine.charAt(startBru - 1))) --startBru;
    let curWordBru = startBru != endBru && currentLine.slice(startBru, endBru);

    // Get JavaScript hints
    const jsHinter = CodeMirror.hint.javascript;
    let result = jsHinter(editor) || { list: [] };
    result.from = CodeMirror.Pos(cursor.line, start);
    result.to = CodeMirror.Pos(cursor.line, end);

    // Add custom brunoJS hints
    if (curWordBru) {
      hintWords.forEach((hint) => {
        if (hint.includes('.') === curWordBru.includes('.') && hint.startsWith(curWordBru)) {
          result.list.push(curWordBru.includes('.') ? hint.split('.')?.at(-1) : hint);
        }
      });
      result.list.sort();
    }

    return result;
  });

  CodeMirror.commands.autocomplete = (cm, hint, options) => {
    cm.showHint({ hint, ...options });
  };
}

export default class CodeEditor extends React.Component {
  constructor(props) {
    super(props);

    // Keep a cached version of the value, this cache will be updated when the
    // editor is updated, which can later be used to protect the editor from
    // unnecessary updates during the update lifecycle.
    this.cachedValue = props.value || '';
    this.variables = {};
    this.searchResultsCountElementId = 'search-results-count';

    this.lintOptions = {
      esversion: 11,
      expr: true,
      asi: true
    };

    this.mockVarsNames = [
      '$guid',
      '$timestamp',
      '$isoTimestamp',
      '$randomUUID',
      '$randomAlphaNumeric',
      '$randomBoolean',
      '$randomInt',
      '$randomColor',
      '$randomHexColor',
      '$randomAbbreviation',
      '$randomIP',
      '$randomIPV4',
      '$randomIPV6',
      '$randomMACAddress',
      '$randomPassword',
      '$randomLocale',
      '$randomUserAgent',
      '$randomProtocol',
      '$randomSemver',
      '$randomFirstName',
      '$randomLastName',
      '$randomFullName',
      '$randomNamePrefix',
      '$randomNameSuffix',
      '$randomJobArea',
      '$randomJobDescriptor',
      '$randomJobTitle',
      '$randomJobType',
      '$randomPhoneNumber',
      '$randomPhoneNumberExt',
      '$randomCity',
      '$randomStreetName',
      '$randomStreetAddress',
      '$randomCountry',
      '$randomCountryCode',
      '$randomLatitude',
      '$randomLongitude',
      '$randomAvatarImage',
      '$randomImageUrl',
      '$randomAbstractImage',
      '$randomAnimalsImage',
      '$randomBusinessImage',
      '$randomCatsImage',
      '$randomCityImage',
      '$randomFoodImage',
      '$randomNightlifeImage',
      '$randomFashionImage',
      '$randomPeopleImage',
      '$randomNatureImage',
      '$randomSportsImage',
      '$randomTransportImage',
      '$randomImageDataUri',
      '$randomBankAccount',
      '$randomBankAccountName',
      '$randomCreditCardMask',
      '$randomBankAccountBic',
      '$randomBankAccountIban',
      '$randomTransactionType',
      '$randomCurrencyCode',
      '$randomCurrencyName',
      '$randomCurrencySymbol',
      '$randomBitcoin',
      '$randomCompanyName',
      '$randomCompanySuffix',
      '$randomBs',
      '$randomBsAdjective',
      '$randomBsBuzz',
      '$randomBsNoun',
      '$randomCatchPhrase',
      '$randomCatchPhraseAdjective',
      '$randomCatchPhraseDescriptor',
      '$randomCatchPhraseNoun',
      '$randomDatabaseColumn',
      '$randomDatabaseType',
      '$randomDatabaseCollation',
      '$randomDatabaseEngine',
      '$randomDateFuture',
      '$randomDatePast',
      '$randomDateRecent',
      '$randomWeekday',
      '$randomMonth',
      '$randomDomainName',
      '$randomDomainSuffix',
      '$randomDomainWord',
      '$randomEmail',
      '$randomExampleEmail',
      '$randomUserName',
      '$randomUrl',
      '$randomFileName',
      '$randomFileType',
      '$randomFileExt',
      '$randomCommonFileName',
      '$randomCommonFileType',
      '$randomCommonFileExt',
      '$randomFilePath',
      '$randomDirectoryPath',
      '$randomMimeType',
      '$randomPrice',
      '$randomProduct',
      '$randomProductAdjective',
      '$randomProductMaterial',
      '$randomProductName',
      '$randomDepartment',
      '$randomNoun',
      '$randomVerb',
      '$randomIngverb',
      '$randomAdjective',
      '$randomWord',
      '$randomWords',
      '$randomPhrase',
      '$randomLoremWord',
      '$randomLoremWords',
      '$randomLoremSentence',
      '$randomLoremSentences',
      '$randomLoremParagraph',
      '$randomLoremParagraphs',
      '$randomLoremText',
      '$randomLoremSlug',
      '$randomLoremLines'
    ];
  }

  componentDidMount() {
    const editor = (this.editor = CodeMirror(this._node, {
      value: this.props.value || '',
      lineNumbers: true,
      lineWrapping: true,
      tabSize: TAB_SIZE,
      mode: this.props.mode || 'application/ld+json',
      keyMap: 'sublime',
      autoCloseBrackets: true,
      matchBrackets: true,
      showCursorWhenSelecting: true,
      foldGutter: true,
      gutters: ['CodeMirror-linenumbers', 'CodeMirror-foldgutter', 'CodeMirror-lint-markers'],
      lint: this.lintOptions,
      readOnly: this.props.readOnly,
      scrollbarStyle: 'overlay',
      theme: this.props.theme === 'dark' ? 'monokai' : 'default',
      extraKeys: {
        'Cmd-Enter': () => {
          if (this.props.onRun) {
            this.props.onRun();
          }
        },
        'Ctrl-Enter': () => {
          if (this.props.onRun) {
            this.props.onRun();
          }
        },
        'Cmd-S': () => {
          if (this.props.onSave) {
            this.props.onSave();
          }
        },
        'Ctrl-S': () => {
          if (this.props.onSave) {
            this.props.onSave();
          }
        },
        'Cmd-F': (cm) => {
          if (this._isSearchOpen()) {
            // replace the older search component with the new one
            const search = document.querySelector('.CodeMirror-dialog.CodeMirror-dialog-top');
            search && search.remove();
          }
          cm.execCommand('findPersistent');
          this._bindSearchHandler();
          this._appendSearchResultsCount();
        },
        'Ctrl-F': (cm) => {
          if (this._isSearchOpen()) {
            // replace the older search component with the new one
            const search = document.querySelector('.CodeMirror-dialog.CodeMirror-dialog-top');
            search && search.remove();
          }
          cm.execCommand('findPersistent');
          this._bindSearchHandler();
          this._appendSearchResultsCount();
        },
        'Cmd-H': 'replace',
        'Ctrl-H': 'replace',
        Tab: function (cm) {
          cm.getSelection().includes('\n') || editor.getLine(cm.getCursor().line) == cm.getSelection()
            ? cm.execCommand('indentMore')
            : cm.replaceSelection('  ', 'end');
        },
        'Shift-Tab': 'indentLess',
        'Ctrl-Space': 'autocomplete',
        'Cmd-Space': 'autocomplete',
        'Ctrl-Y': 'foldAll',
        'Cmd-Y': 'foldAll',
        'Ctrl-I': 'unfoldAll',
        'Cmd-I': 'unfoldAll',
        'Ctrl-/': () => {
          if (['application/ld+json', 'application/json'].includes(this.props.mode)) {
            this.editor.toggleComment({ lineComment: '//', blockComment: '/*' });
          } else {
            this.editor.toggleComment();
          }
        },
        'Cmd-/': () => {
          if (['application/ld+json', 'application/json'].includes(this.props.mode)) {
            this.editor.toggleComment({ lineComment: '//', blockComment: '/*' });
          } else {
            this.editor.toggleComment();
          }
        }
      },
      foldOptions: {
        widget: (from, to) => {
          var count = undefined;
          var internal = this.editor.getRange(from, to);
          if (this.props.mode == 'application/ld+json') {
            if (this.editor.getLine(from.line).endsWith('[')) {
              var toParse = '[' + internal + ']';
            } else var toParse = '{' + internal + '}';
            try {
              count = Object.keys(JSON.parse(toParse)).length;
            } catch (e) {}
          } else if (this.props.mode == 'application/xml') {
            var doc = new DOMParser();
            try {
              //add header element and remove prefix namespaces for DOMParser
              var dcm = doc.parseFromString(
                '<a> ' + internal.replace(/(?<=\<|<\/)\w+:/g, '') + '</a>',
                'application/xml'
              );
              count = dcm.documentElement.children.length;
            } catch (e) {}
          }
          return count ? `\u21A4${count}\u21A6` : '\u2194';
        }
      }
    }));
    CodeMirror.registerHelper('lint', 'json', function (text) {
      let found = [];
      if (!window.jsonlint) {
        if (window.console) {
          window.console.error('Error: window.jsonlint not defined, CodeMirror JSON linting cannot run.');
        }
        return found;
      }
      let jsonlint = window.jsonlint.parser || window.jsonlint;
      try {
        jsonlint.parse(stripJsonComments(text.replace(/(?<!"[^":{]*){{[^}]*}}(?![^"},]*")/g, '1')));
      } catch (error) {
        const { message, location } = error;
        const line = location?.start?.line;
        const column = location?.start?.column;
        if (line && column) {
          found.push({
            from: CodeMirror.Pos(line - 1, column),
            to: CodeMirror.Pos(line - 1, column),
            message
          });
        }
      }
      return found;
    });
    if (editor) {
      editor.setOption('lint', this.props.mode && editor.getValue().trim().length > 0 ? this.lintOptions : false);
      editor.on('change', this._onEdit);
      this.addOverlay();
    }
    
    if (this.props.mode == 'javascript') {
      editor.on('keyup', function (cm, event) {
        const cursor = editor.getCursor();
        const currentLine = editor.getLine(cursor.line);
        let start = cursor.ch;
        let end = start;
    
        const isWordChar = char => /[^{}();\s\[\]\,]/.test(char);
    
        while (end < currentLine.length && isWordChar(currentLine.charAt(end))) ++end;
        while (start && isWordChar(currentLine.charAt(start - 1))) --start;
    
        let curWord = start != end && currentLine.slice(start, end);
    
        const isValidKey = /^(?!Shift|Tab|Enter|Escape|ArrowUp|ArrowDown|ArrowLeft|ArrowRight|Meta|Alt|Home|End\s)\w*/.test(event.key);
        const isNotInCommentOrTemplate = !/\/\/|\/\*|.*{{|`[^$]*{|`[^{]*$/.test(currentLine.slice(0, end));
        const isValidWordEnding = /(?<!\d)[a-zA-Z\._]$/.test(curWord);
    
        if (isValidKey && curWord.length > 0 && isNotInCommentOrTemplate && isValidWordEnding) {
          CodeMirror.commands.autocomplete(cm, CodeMirror.hint.brunoJS, { completeSingle: false });
        }
      });
    }

    const getHints = (cm) => {
      const cursor = cm.getCursor();
      const currentString = cm.getRange({ line: cursor.line, ch: 0 }, cursor);
    
      const match = currentString.match(/\{\{\$(\w*)$/);
      if (!match) return null;
        
      const wordMatch = match[1];
      if (!wordMatch) return null;
    
      const suggestions = this.mockVarsNames.filter((name) => name.startsWith(`$${wordMatch}`));
      if (!suggestions.length) return null;
    
      const startPos = { line: cursor.line, ch: currentString.lastIndexOf('{{$') + 2 }; // +2 accounts for `{{
    
      return {
        list: suggestions,
        from: startPos,
        to: cm.getCursor(),
      };
    };

    editor.on('inputRead', function (cm, event) {
      const hints = getHints(cm);
      if (!hints) {
        return;
      }
        
      cm.showHint({
        hint: () => hints,
        completeSingle: false,
      });
    });
  }

  componentDidUpdate(prevProps) {
    // Ensure the changes caused by this update are not interpreted as
    // user-input changes which could otherwise result in an infinite
    // event loop.
    this.ignoreChangeEvent = true;
    if (this.props.schema !== prevProps.schema && this.editor) {
      this.editor.options.lint.schema = this.props.schema;
      this.editor.options.hintOptions.schema = this.props.schema;
      this.editor.options.info.schema = this.props.schema;
      this.editor.options.jump.schema = this.props.schema;
      CodeMirror.signal(this.editor, 'change', this.editor);
    }
    if (this.props.value !== prevProps.value && this.props.value !== this.cachedValue && this.editor) {
      this.cachedValue = this.props.value;
      this.editor.setValue(this.props.value);
    }

    if (this.editor) {
      let variables = getAllVariables(this.props.collection, this.props.item);
      if (!isEqual(variables, this.variables)) {
        this.addOverlay();
      }
    }

    if (this.props.theme !== prevProps.theme && this.editor) {
      this.editor.setOption('theme', this.props.theme === 'dark' ? 'monokai' : 'default');
    }
    this.ignoreChangeEvent = false;
  }

  componentWillUnmount() {
    if (this.editor) {
      this.editor.off('change', this._onEdit);
      this.editor = null;
    }

    this._unbindSearchHandler();
  }

  render() {
    if (this.editor) {
      this.editor.refresh();
    }
    return (
      <StyledWrapper
        className="h-full w-full flex flex-col relative graphiql-container"
        aria-label="Code Editor"
        font={this.props.font}
        fontSize={this.props.fontSize}
        ref={(node) => {
          this._node = node;
        }}
      />
    );
  }

  addOverlay = () => {
    const mode = this.props.mode || 'application/ld+json';
    let variables = getAllVariables(this.props.collection, this.props.item);
    this.variables = variables;

    defineCodeMirrorBrunoVariablesMode(variables, mode);
    this.editor.setOption('mode', 'brunovariables');
  };

  _onEdit = () => {
    if (!this.ignoreChangeEvent && this.editor) {
      this.editor.setOption('lint', this.editor.getValue().trim().length > 0 ? this.lintOptions : false);
      this.cachedValue = this.editor.getValue();
      if (this.props.onEdit) {
        this.props.onEdit(this.cachedValue);
      }
    }
  };

  _isSearchOpen = () => {
    return document.querySelector('.CodeMirror-dialog.CodeMirror-dialog-top');
  };

  /**
   * Bind handler to search input to count number of search results
   */
  _bindSearchHandler = () => {
    const searchInput = document.querySelector('.CodeMirror-search-field');

    if (searchInput) {
      searchInput.addEventListener('input', this._countSearchResults);
    }
  };

  /**
   * Unbind handler to search input to count number of search results
   */
  _unbindSearchHandler = () => {
    const searchInput = document.querySelector('.CodeMirror-search-field');

    if (searchInput) {
      searchInput.removeEventListener('input', this._countSearchResults);
    }
  };

  /**
   * Append search results count to search dialog
   */
  _appendSearchResultsCount = () => {
    const dialog = document.querySelector('.CodeMirror-dialog.CodeMirror-dialog-top');

    if (dialog) {
      const searchResultsCount = document.createElement('span');
      searchResultsCount.id = this.searchResultsCountElementId;
      dialog.appendChild(searchResultsCount);

      this._countSearchResults();
    }
  };

  /**
   * Count search results and update state
   */
  _countSearchResults = () => {
    let count = 0;

    const searchInput = document.querySelector('.CodeMirror-search-field');

    if (searchInput && searchInput.value.length > 0) {
      // Escape special characters in search input to prevent RegExp crashes. Fixes #3051
      const text = new RegExp(escapeRegExp(searchInput.value), 'gi');
      const matches = this.editor.getValue().match(text);
      count = matches ? matches.length : 0;
    }

    const searchResultsCountElement = document.querySelector(`#${this.searchResultsCountElementId}`);

    if (searchResultsCountElement) {
      searchResultsCountElement.innerText = `${count} results`;
    }
  };
}
