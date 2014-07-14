import click
import urllib
import urllib2
import hashlib
import re
import xml.dom.minidom
import time



############################################
#based on vNAM version 6.0.1 reference guide
#http://www.cisco.com/c/dam/en/us/td/docs/net_mgmt/network_analysis_module_software/6-0-2/developer/guide/nam-rest-api-guide.pdf


############################################
Global_API_uri_NTP ='/nbi/nbi-ntp'
Global_API_uri_CSV ='/nbi/nbi-csvquery'
Global_API_uri_Sysinfo ='/nbi/nbi-system'
Global_API_uri_Application='/nbi/nbi-apps'
Global_NAM_timeformat = '%Y-%b-%d, %H:%M:%S '

Global_CoreConv_query = '''<query-data>
 <query>
  SELECT time,site1,addr1,site2,addr2,appId,ipProtocol,octets1to2,octets2to1, inIf, outIf,packets1to2,packets2to1,serverPort,dataSource
  FROM CoreConv
  WHERE TIME &gt;= %s AND TIME &lt;= %s
  LIMIT 100, 1
 </query>
</query-data>'''


############################################
#autheticate the NAM and return cookies
def get_auth_url(ip, user, pswd):
    base_url = 'http://%s/auth/' % ip
    init_url = base_url + 'login.php?api=true'
    try:
        res = urllib2.urlopen(urllib2.Request(init_url),timeout=5)
    except:
##        print 'NAM access timeout'
        return '',''
    cookie = res.headers.get('Set-Cookie')

    kv_list = []
    for l in res.read().splitlines():
        k, v = l.split('=')
        kv_list.append((k, v))

    password_hash = hashlib.sha1("04581273"+user+pswd).hexdigest()
    m = hashlib.md5()
    for k, v in kv_list[:2]:
        m.update(v)
    m.update(user + password_hash)
    pw = m.hexdigest()
    
    session_id = kv_list[-1][1]
    url = 'authenticate.php?sessid=%s&username=%s&pwdigest=%s&pkey=%s'
    auth_url = base_url + url % (session_id, user, pw, kv_list[-2][1])
##    print 'Authenticate URL:\n' + auth_url
    return auth_url, cookie


############################################
#NAM API funciton(nam_url, api, method,query_methond,options)
def NAM_api(nam_url,uri,method,query_method,options):
    r = [m.start() for m in re.finditer('/', nam_url[0])]
    api_url=nam_url[0]
    api_url=api_url[:r[2]]+uri

    
    if uri==Global_API_uri_CSV:
        reqObj = urllib2.Request(api_url,query_method)
    else:        
        reqObj = urllib2.Request(api_url)

    reqObj.add_header('cookie', nam_url[1])    
    try:
        reqResult = urllib2.urlopen(reqObj,timeout=5).read()
    except:
        print 'NAM access timeout'
        return False
##        print reqResult

    return xml.dom.minidom.parseString(reqResult)
   
##    if uri==Global_API_uri_NTP:
##        return doc.getElementsByTagName("time")[0].childNodes[0].nodeValue,doc.getElementsByTagName("region")[0].childNodes[0].nodeValue,doc.getElementsByTagName("description")[0].childNodes[0].nodeValue
##    elif uri==Global_API_uri_Sysinfo:
##        return Flase       



##############################################
###set and get NAM system time setting
##def NAM_NTP(nam_url, currenttime, setflag):
##    query=''
####    reqObj=urllib2.Request(nam_url[0])
####    reqResult = urllib2.urlopen(reqObj).read()
####    print reqResult
##
##
##    if setflag == True:
##        print 'NTP adjusting no implemented'
##    else:
####        print 'get time'
####        print Global_API_uri_NTP
####        print nam_url
##        #extract http/https:host:port string
##        r = [m.start() for m in re.finditer('/', nam_url[0])]
##        api_url=nam_url[0]
##        api_url=api_url[:r[2]]+Global_API_uri_NTP
####        print api_url
##
##        
##        reqObj = urllib2.Request(api_url)
####        print nam_url
##        
##        reqObj.add_header('cookie', nam_url[1])    
##        try:
##            reqResult = urllib2.urlopen(reqObj,timeout=5).read()
##        except:
##            print 'NAM access timeout'
##            return False
####        print reqResult
##        doc = xml.dom.minidom.parseString(reqResult)
##        return doc.getElementsByTagName("time")[0].childNodes[0].nodeValue,doc.getElementsByTagName("region")[0].childNodes[0].nodeValue,doc.getElementsByTagName("description")[0].childNodes[0].nodeValue
##
##

############################################
#main module
    
@click.command()
@click.option('-b',help='NAM configuration file',default='')
def main(b):



    #define NAM gorups 
    nam_info=[] #NAM structs for IP/username/password
    nam_list={}  #NAM dict for IP/URL/Cookie
    auth_url=''
    cookie=''


    #populate NAM device info with IP and credentials
    if b!='':
        #batch mode to run this program
        print 'reading NAM configuration file...'
    else:
        #interactive mode for NAM parameters input
        click.echo('please input NAM parameters')
        nam_ip=click.prompt('ip address:', default='192.168.254.156')
        nam_username=click.prompt('username:', default='admin')
        nam_password=click.prompt('password:', default='cisco')
        nam_info=[(nam_ip,nam_username,nam_password,'test','tset')]


    #populate NAM device list with URLs and cookies
    for nam_device in nam_info:
        auth_url, cookie = get_auth_url(nam_device[0],nam_device[1],nam_device[2])
        if auth_url!='' and cookie!='':
            nam_list[nam_device[0]]=auth_url, cookie
##            print nam_list
        else:        
            print 'NAM socket error for %s' % nam_device[0]

#menu options

    while True:
        click.echo('\n=====please select option========')
        click.echo('1. Get NAM datetime')
        click.echo('2. Get NAM system information')
        click.echo('3. Get Applications')
        click.echo('4. Get CoreConv list')
        click.echo('q. Quit')

        menu_option=click.prompt('NAM function choice:',default='4')

        if menu_option == '1':#get NAM current time

            for nam_ip, dummy in nam_list.items():
                doc = NAM_api(nam_list[nam_ip],Global_API_uri_NTP,'get','',[])
                nam_result = doc.getElementsByTagName("time")[0].childNodes[0].nodeValue,doc.getElementsByTagName("region")[0].childNodes[0].nodeValue,doc.getElementsByTagName("status")[0].childNodes[0].nodeValue

                print '\n\n\nNAM information: \n-----------\nIP:%s' %nam_ip
                print 'Time:%s \nZone:%s \nStatus:%s \n-------------' %nam_result

        elif menu_option=='2':#get status of NAM cdb files 

            for nam_ip, dummy in nam_list.items():
                doc = NAM_api(nam_list[nam_ip],Global_API_uri_Sysinfo,'get','',[])
                root=doc.documentElement
                cdbfiles= root.getElementsByTagName('file')

                for n in cdbfiles:  
##                    if 'CoreConv.cdb' == n.getElementsByTagName('name')[0].childNodes[0].nodeValue:
                        print '\n%s record range:' %n.getElementsByTagName('name')[0].childNodes[0].nodeValue                    
                        print '         %s' %time.ctime(float(n.getElementsByTagName('oldestDataTime')[0].childNodes[0].nodeValue)).strip()
                        print '         %s' %time.ctime(float(n.getElementsByTagName('newestDataTime')[0].childNodes[0].nodeValue)).strip()
        elif menu_option=='3':#get lattest content of Applications

            appdict={}
            doc = NAM_api(nam_list[nam_ip],Global_API_uri_Application,'get','',[])
            root=doc.documentElement
            applicationid= root.getElementsByTagName('applicationId')

            for n in applicationid:  
                appdict[n.getElementsByTagName('appTag')[0].childNodes[0].nodeValue]=n.getElementsByTagName('name')[0].childNodes[0].nodeValue

            print appdict
            
        elif menu_option=='4':#get content of CoreConv database

            #get NAM current time
            doc = NAM_api(nam_list[nam_ip],Global_API_uri_NTP,'get','',[])
            nam_currenttime = doc.getElementsByTagName("time")[0].childNodes[0].nodeValue
##            print nam_currenttime
##            print time.strptime(nam_currenttime[:len(nam_currenttime)-3],Global_NAM_timeformat)
##            print time.mktime(time.strptime(nam_currenttime[:len(nam_currenttime)-3],Global_NAM_timeformat))
            nam_currenttime_int=int(time.mktime(time.strptime(nam_currenttime[:len(nam_currenttime)-3],Global_NAM_timeformat)))
            currenttime=time.time()
            query_string = Global_CoreConv_query %(str(nam_currenttime_int-3600), str(nam_currenttime_int))
            currenttime=time.time()-currenttime    
            doc = NAM_api(nam_list[nam_ip],Global_API_uri_CSV,'get',query_string,[])
            root=doc.documentElement
            applicationid= root.getElementsByTagName('query-data')
            if 'Successful'== root.getElementsByTagName('description')[0].childNodes[0].nodeValue:

                for n in applicationid:
                    print 'Return %d rows' %len(n.getElementsByTagName('row'))
                    print 'in %f seconds' %currenttime
                    for i in range(0,len(n.getElementsByTagName('row'))-1):
                        print n.getElementsByTagName('row')[i].childNodes[0].nodeValue
                    
            else:
                print 'CDB Query response failed with error %s' %root.getElementsByTagName('description')[0].childNodes[0].nodeValue

##            print appdict            


        elif menu_option=='q':
            return
            

############################################
#main entry
if __name__=='__main__':
    main()
