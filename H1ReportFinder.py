__author__ = 'Kareem Selim'
__date__ = '2020508'
__version__ = '0.01'
__description__ = """

A burpsuite extension that helps security researchers 
find public security reports published on h1 
corresponding to the selected host/url 

"""


from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab

from java.util import ArrayList
from javax.swing import JMenuItem
from javax.swing import JPanel
from javax.swing import JTable
from javax.swing import JScrollPane
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout,Dimension

import requests
import tldextract
from bs4 import BeautifulSoup

import threading
import sys



class BurpExtender(IBurpExtender, ITab,IContextMenuFactory):

    EXTENSION_NAME="H1 Report Finder" 
    API='http://h1.nobbd.de/search.php?q='
	
    def registerExtenderCallbacks(self, callbacks):
	
        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("H1 Report Finder")
        callbacks.registerContextMenuFactory(self)
        # Create the tab
        self.tab = JPanel(BorderLayout())
		
		#Create an empty Table
        self.tableData = []
        self.colNames = ('Vendor','Hunter','Vulnerability','Report','Date')
        self.dataModel = DefaultTableModel(self.tableData, self.colNames)
        self.table = Table(self.dataModel)
        self.scrollPane = JScrollPane(self.table)
        self.scrollPane.setPreferredSize(Dimension(500,500))

        self.tab.add(self.scrollPane, BorderLayout.NORTH)
		
        callbacks.customizeUiComponent(self.tab) 
        callbacks.addSuiteTab(self)
        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Find Reports for Selected Host",
                              actionPerformed=self.populateTable)
        menuList.add(menuItem)
        return menuList

    #Fetch Reports
    def getReports(self,host):
        datalist=[]
        minilist=[]
        res = requests.get(self.API+host)
        if (res.status_code == 200) :
          soup=BeautifulSoup(res.text, 'html.parser')
          reports=soup.findAll("div", {"class": "report-wrapper"})
          reportDates=soup.findAll("div", {"class": "date"})
          for i in range(len(reports)):
            w=reports[i].find(class_='report').find(class_='company').text   #Vendor
            x=reports[i].find(class_='report').find(class_='submitter').text #Hunter
            y=reports[i].find(class_='report').find(class_='title').text     #Vulnerability
            z=reports[i].find(class_='report').find(class_='title')['href']  #Report
            q=reportDates[i].text
            print x+'|'+y+'|'+z+'|'+q
			
            minilist.append(w)
            minilist.append(x)
            minilist.append(y)
            minilist.append(z)
            minilist.append(q)
            datalist.append(minilist)
            minilist=[]
          for report in datalist:
           self.table.getModel().addRow(report)


    def populateTable(self,event):
	    #Clear Table Entries
        self.table.getModel().setNumRows(0)   
        Res= self.context.getSelectedMessages()       
        host=tldextract.extract(Res[0].getHttpService().getHost())
        baseUrl=host.domain+'.'+host.suffix
		#Fetch Reports in a new thread
        t = threading.Thread(target=self.getReports,args=[baseUrl])
        t.daemon = True
        t.start()
        print 	baseUrl
         		
		
    def getTabCaption(self): 
      return self.EXTENSION_NAME

    def getUiComponent(self): 
      return self.tab 
	  
	  
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
		
    def isCellEditable( self, row, col ) :
        return True
		
    def setValueAt(self, value,row,col):
	    return 
