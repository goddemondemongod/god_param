#coding:utf-8
#Author:goddmeon
#Date:20230323
#Description:god_param
import json
import re
import os
import locale
import java.nio.charset.Charset as Charset

from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener, IContextMenuFactory
from javax.swing import JPanel, JLabel, JButton, JTextArea, JTextField, JCheckBox, JTabbedPane, JScrollPane, SwingConstants, JFileChooser, JList, JOptionPane
from java.awt import BorderLayout, Font, Color

from java.io import PrintWriter

pattern = r'[?&/.;]'
regex = {
    "Linker": r'(?:"|\')((?!text\/javascript)((?:[a-zA-Z]{1,10}://|//)[^"\'/]{1,}\.[a-zA-Z]{2,}[^"\']{0,})|((?:/|\.\./|\./)[^"\'><,;|*()(%%$^/\\\[\]][^"\'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|\']{0,}|)))(?:"|\')',
}
sensitiveParamsFile = "sensitive-params.txt"
ParamsFile="params.txt"
def getSensitiveParamsFromFile():
    with open(sensitiveParamsFile) as spf:
        return [line.strip() for line in spf.readlines()]

class BurpExtender(IBurpExtender, ITab,IHttpListener,IExtensionStateListener):
    def __init__(self):
        self.target_whitelist = []  # 添加你的白名单目标


    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("god_param")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        print 'Author: goddemon\n'
        print 'Consulttools: burp-sensitive-param-extractor\n'
        print 'Thanks: LSA'
        self._callbacks.customizeUiComponent(self.getUiComponent())
        self._callbacks.addSuiteTab(self)
        self.requestParamDict = {}
        self.resultSensitiveParamsDict = {}

    def getTabCaption(self):
        return 'god_param'
    #提取参数
    def extract_param_names(self,content,max_length=15):
        routes = []
        for name, pattern in regex.items():
            matches = re.findall(pattern, content)
            for match in matches:
                route = match[0].encode('ascii', 'ignore').decode()
                if route not in routes:
                    routes.append(route)
        return routes  

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        service = messageInfo.getHttpService()
        host = service.getHost()
        
        # 如果目标主机不在白名单中，直接返回
        if host not in self.target_whitelist:
            return        
        if messageIsRequest :
            self.requestParamDict['urlParams'] = []
            self.requestParamDict['bodyParams'] = []
            self.requestParamDict['cookieParams'] = []
            self.requestParamDict['jsonParams'] = []
            cookieParamFlag = 0
            service = messageInfo.getHttpService()
            request = messageInfo.getRequest() 
            reqUrl = self._helpers.analyzeRequest(messageInfo).getUrl()
            reqMethod = self._helpers.analyzeRequest(messageInfo).getMethod()
            analyzeReq = self._helpers.analyzeRequest(service,request)#使用原生的Burp Suite API方法，用来分析HTTP请求以获取各种信息。
            for param in analyzeReq.getParameters():
                if param.getType() == 0:
                   self.requestParamDict['urlParams'].append(param.getName().strip())
                elif param.getType() == 1:
                   self.requestParamDict['bodyParams'].append(param.getName().strip())
                elif param.getType() == 2:
                   self.requestParamDict['cookieParams'].append(param.getName().strip())
                elif param.getType() == 6:
                   self.requestParamDict['jsonParams'].append(param.getName().strip())
            self.resultSensitiveParamsDict = self.findSensitiveParam(self.requestParamDict)

            for rspdKey in self.resultSensitiveParamsDict.keys():#这里进行输路由和方法类型
                if self.resultSensitiveParamsDict[rspdKey] != []:
                    self.outputTxtArea.append("\n------------------------------------------------------\n")
                    self.outputTxtArea.append("[%s][%s]\n" % (reqMethod,reqUrl))
                    break

            for rspdKey in self.resultSensitiveParamsDict.keys():#这里进行输出参数以及参数值
                if self.resultSensitiveParamsDict[rspdKey] != []:    
                    self.outputTxtArea.append("\n"+rspdKey+"--"+str(self.resultSensitiveParamsDict[rspdKey]))
            self.write2file()
        else:
          if messageInfo.getResponse():
              response = messageInfo.getResponse()
              analyzedResponse  = self._helpers.analyzeResponse(response) # 使用原生的Burp Suite API方法，用来分析HTTP响应以获取各种信息。
              statusCode = analyzedResponse.getStatusCode()  # 获取响应状态码
              headers = analyzedResponse.getHeaders()  # 获取响应头部信息
              body = response[analyzedResponse.getBodyOffset():].tostring()  # 获取HTTP响应的正文部分
              body1=self.extract_param_names(body)
              params_str = ''.join(body1)
              self.resultSensitiveParams = re.findall(r'[\?&]([^=&]+)=', params_str)#这里是提取到的参数
              newSensitiveParamsList = []
              sensitiveParamsList = set(getSensitiveParamsFromFile())
              for param in self.resultSensitiveParams:
                  if param not in sensitiveParamsList and param not in newSensitiveParamsList:
                      newSensitiveParamsList.append(param)
                      sensitiveParamsList.add(param)
              with open(sensitiveParamsFile, 'a') as spf:
                  if newSensitiveParamsList :
                      for param in newSensitiveParamsList:
                          if "}" not in param and ";" not in param and "{" not in param and "," not in param and "|" not in param and "/" not in param and "?" not in param:
                                 spf.write(param + '\n')
          else:
              print("没有收到响应") 


    # IExtensionStateListener 接口方法
    def extensionUnloaded(self):
        self.CacheFileunLoad(sensitiveParamsFile)        
    # 缓冲文件删除
    def CacheFileunLoad(self,path):
        with open(path, 'w') as f:
             f.write('')

#进行匹配返回键值对的作用
#创建了一个名为resultSensitiveParamsDict的新字典，包括四个键值对，其值全部设置为空列表。然后，我们遍历传递给该函数的字典中的每个项。对于每个项，我们遍历其中的每个参数名称，对于每个参数名称，我们检查其是否与一组正则表达式匹配。如果找到匹配，则将该参数的名称添加到相应参数类型的resultSensitiveParamsDict字典值中
    def findSensitiveParam(self, requestParamDict):
        resultSensitiveParamsDict = {'urlParams': [], 'bodyParams': [], 'cookieParams': [], 'jsonParams': []}
        for key in requestParamDict:
            for paramName in requestParamDict[key]:
                    resultSensitiveParamsDict[key].append(paramName)
        return resultSensitiveParamsDict



    def write2file(self):
        if isinstance(self.resultSensitiveParamsDict, dict):
            sensitiveParamsList = set(getSensitiveParamsFromFile())
            newSensitiveParamsList = set()
            for key, value in self.resultSensitiveParamsDict.items():
                if isinstance(value, list) and value:
                    for param in value:
                        if param not in sensitiveParamsList:
                           newSensitiveParamsList.add(param)
                           sensitiveParamsList.add(param)

            with open(sensitiveParamsFile, 'a') as spf:  
               if newSensitiveParamsList :  
                   for param in newSensitiveParamsList:  
                          if "}" not in param and ";" not in param and "{" not in param and "," not in param and "|" not in param and "/" not in param and "?" not in param:
                             spf.write(param + '\n')
        else:
            print("resultSensitiveParamsDict is not a dictionary")

    def copySensitiveParamsToFile(self):
        with open(sensitiveParamsFile) as spf:
             content = spf.read()
        with open(ParamsFile, 'w') as f:
             f.write(content)
    

    def clearRst(self, event):
          self.CacheFileunLoad(sensitiveParamsFile)
          self.CacheFileunLoad(ParamsFile)
          self.outputTxtArea.setText("")
          sensitiveParamsList=""
          newSensitiveParamsList=""
          self.sensitiveParamsRegularTextArea.setText("")

    def readRst(self, event):
          self.copySensitiveParamsToFile()  # 先复制 sensitive-params.txt 的内容到 a.txt 文件中
          with open(ParamsFile) as f:
               content = f.read()
               unique_content = set(content.split('\n'))
          self.sensitiveParamsRegularTextArea.setText('\n'.join(unique_content))

    def exportRst(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print "\n" + "Export to : " + filename
        open(filename, 'w', 0).write(self.outputTxtArea.text)




    def startWhitelist(self, event):
        if self.startWhitelistBtn.getText() == "Start Whitelist":
            targets_text = self.targetInput.getText().strip()
            targets_text = str(targets_text)
            targets = targets_text.split(";")
            targets = [target.strip() for target in targets if target.strip()]
            self.target_whitelist = targets
            print("启动白名单：{}".format(self.target_whitelist))
            self.startWhitelistBtn.setText("Stop Whitelist")
        else:
        # 处理停止白名单的逻辑
        # 可以添加一些代码来清空白名单或者停止相关功能
            self.startWhitelistBtn.setText("Start Whitelist")













    def getUiComponent(self):
        defaultCharset = locale.getdefaultlocale()[1]
        self.spePanel = JPanel()
        self.spePanel.setLayout(None)

        # 日志区域
        self.logPane = JScrollPane()
        self.outputTxtArea = JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.logPane.setBounds(20, 50, 800, 600)
        self.spePanel.add(self.logPane)

        # 按钮区域
        self.clearBtn = JButton("Clear", actionPerformed=self.clearRst)
        self.readBtn = JButton("Read", actionPerformed=self.readRst)
        self.exportBtn = JButton("Export", actionPerformed=self.exportRst)
        #self.startBtn = JButton("Start", actionPerformed=self.startRst)

        self.clearBtn.setBounds(20, 670, 100, 30)
        self.readBtn.setBounds(120, 670, 100, 30)
        self.exportBtn.setBounds(220, 670, 100, 30)
        #self.startBtn.setBounds(320, 670, 100, 30)
        self.spePanel.add(self.clearBtn)
        self.spePanel.add(self.readBtn)
        self.spePanel.add(self.exportBtn)
        #self.spePanel.add(self.startBtn)

        # 白名单输入框和按钮
        self.targetInput = JTextField(20)
        self.startWhitelistBtn = JButton("Start Whitelist", actionPerformed=self.startWhitelist)

        self.targetInput.setBounds(520, 670, 150, 30)
        self.startWhitelistBtn.setBounds(675, 670, 150, 30)

        self.spePanel.add(self.targetInput)
        self.spePanel.add(self.startWhitelistBtn)

        # 敏感参数区域
        self.sensitiveParamsRegularTextArea = JTextArea('\n'.join(""))
        self.sensitiveParamsRegularScrollPane = JScrollPane(self.sensitiveParamsRegularTextArea)
        self.sensitiveParamsRegularScrollPane.setBounds(850, 50, 150, 600)
        self.spePanel.add(self.sensitiveParamsRegularScrollPane)

        # 信息展示区域
        self.textLabelAuthor = JLabel()
        self.textLabelAuthor.setText("Author: goddemon".encode(defaultCharset).decode(defaultCharset))
        self.textLabelAuthor.setHorizontalAlignment(SwingConstants.CENTER)
        self.textLabelAuthor.setVerticalAlignment(SwingConstants.TOP)
        self.textLabelAuthor.setBounds(1020, 200, 200, 20)
        self.spePanel.add(self.textLabelAuthor)

        self.textLabelConsult = JLabel()
        self.textLabelConsult.setText("Consulttools:  ".encode(defaultCharset).decode(defaultCharset))
        self.textLabelConsult.setHorizontalAlignment(SwingConstants.CENTER)
        self.textLabelConsult.setVerticalAlignment(SwingConstants.TOP)
        self.textLabelConsult.setBounds(1020, 230, 200, 60)
        self.spePanel.add(self.textLabelConsult)

        self.textLabelConsult = JLabel()
        self.textLabelConsult.setText("burp-sensitive-param-extractor ".encode(defaultCharset).decode(defaultCharset))
        self.textLabelConsult.setHorizontalAlignment(SwingConstants.CENTER)
        self.textLabelConsult.setVerticalAlignment(SwingConstants.TOP)
        self.textLabelConsult.setBounds(1020, 250, 200, 60)
        self.spePanel.add(self.textLabelConsult)

        self.textLabelConsultAuthor = JLabel()
        self.textLabelConsultAuthor.setText("Thanks: LSA".encode(defaultCharset).decode(defaultCharset))
        self.textLabelConsultAuthor.setHorizontalAlignment(SwingConstants.CENTER)
        self.textLabelConsultAuthor.setVerticalAlignment(SwingConstants.TOP)
        self.textLabelConsultAuthor.setBounds(1020, 270, 200, 60)
        self.spePanel.add(self.textLabelConsultAuthor)

        self.alertSaveSuccess = JOptionPane()
        self.spePanel.add(self.alertSaveSuccess)

        return self.spePanel

