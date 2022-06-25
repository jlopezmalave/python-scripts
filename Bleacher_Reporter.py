#!/usr/bin/env python

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.io import File
from java.net import URL

import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Bleacher Reporter')
        self._helpers = self._callbacks.getHelpers()

        self.spider_findings = []
        self.scanner_findings = []
        self.request_timeout = 5

        url = '<Enter the URL to test>'

        self.last_made_request = int(time.time())

        #self._callbacks.sendToSpider(url)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)

        while(int(time.time())-self.last_made_request <= self.request_timeout):
            time.sleep(1)
        print('No more requests have been made to the webservice.')

        self._callbacks.removeHttpListener(self)
        self._callbacks.removeScannerListener(self)
        #self._callbacks.excludeFromScope(url)

        print('Reports being generated...')
        self.generateReport('HTML')
        self.generateReport('XML')

        return

    def processHttpMessage(self, toolFlag, isRequest, current):

        self.last_made_request = int(time.time())
        if(toolFlag == self._callbacks.TOOL_SPIDER and isRequest):
            self.spider_findings.append(current)
        elif(toolFlag == self._callbacks.TOOL_SCANNER and isRequest):
            self.scanner_findings.append(current)
        return

    def newScanIssue(self, issue):

        self.scanner_findings.append(issue)
        return

    def generateReport(self, format):

        if(format == 'HTML'):
            file_name_scanner = '<file path and report name to save the report to.>'+format.lower()
            file_name_spider = '<file path and report name to save the report to.>'+format.lower()
            self._callbacks.generateScanReport(format, self.scanner_findings,File(file_name_scanner))
            self._callbacks.generateScanReport(format, self.spider_findings,File(file_name_spider))
        elif(format == 'XML'):
            file_name_scanner = '<file path and report name to save the report to.>'+format.lower()
            file_name_spider = '<file path and report name to save the report to.>'+format.lower()
            self._callbacks.generateScanReport(format, self.scanner_findings,File(file_name_scanner))
            self._callbacks.generateScanReport(format, self.spider_findings,File(file_name_spider))
        return





