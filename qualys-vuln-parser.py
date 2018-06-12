#!/usr/bin/python

'''
Copyright 2018 Brett Gross :) 

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


import xml.etree.ElementTree as et
import argparse, time, ldap

debug = False

parser = argparse.ArgumentParser(description='Process me some Qualys reports. Nom nom.')
parser.add_argument('--vuln_report', metavar="<vuln_report>", type=str, help='Filename of vulnerability report')
parser.add_argument('--kb_report', metavar="<kb_report>", type=str, help='Filename of knowledge-base report')
parser.add_argument('--output_file', metavar="<outputfile>", type=str, help='Output filename. Defaults to "parsed-report-[epoch timestamp].qualys" in cwd if none provided.')


def ldapConnect(username='', password='', server='<domain_controller>', distinguished=True, attempts=0):
    global baseDN, l, valid
    valid = False
    
    baseDN = 'dc=domain,dc=tld'

    l = ldap.initialize('ldap://%s:3268' % server)  
            
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(username, password)
        l.set_option(ldap.OPT_REFERRALS,0)
        valid = True
    except(ldap.INVALID_CREDENTIALS):
        return False
    except Exception, error:
        print error
        return False
    
    return True

def ldapSearch(searchFilter = 'none', retrieveAttributes = None):
    global valid
    
    searchScope = ldap.SCOPE_SUBTREE
    result_set = []
    
    if valid:
        try:
            ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        
            while True:
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    ## here you don't have to append to a list
                    ## you could do whatever you want with the individual entry
                    ## The appending to list is just for illustration. 
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
        except ldap.LDAPError, e:
            print e
         
    return result_set


# KNOWLEDGE_BASE_VULN_LIST
def parseKB(vuln_kb_filename):
	# parse parse parse
	tree = et.parse(vuln_kb_filename)
	root = tree.getroot()
	# Get the VULN_LIST tag from the RESPONSE tag.
	vuln_list = root.find("RESPONSE").getchildren()[1]
	vuln_tag_list = ["VULN_TYPE", "TITLE", "CATEGORY", "LAST_SERVICE_MODIFICATION_DATETIME", "PUBLISHED_DATETIME", "PATCHABLE", "PCI_FLAG", "DIAGNOSIS", "CONSEQUENCE", "SOLUTION", "SUPPORTED_MODULES"]
	vuln_kb_dict = {}
	for vuln in vuln_list:
		qid = vuln.find("QID").text
		if qid not in vuln_kb_dict:
			vuln_kb_dict[qid] = {}
		else:
			print("qid [%s] already used." % qid)

		for tag in vuln_tag_list:
			try:
				vuln_kb_dict[qid][tag.lower()] = vuln.find(tag).text.replace("\"", "'")
			except (AttributeError):
				if debug:
					print("Error: tag [%s] could not be retrieved." % tag)
				pass
		try:
			vuln_kb_dict[qid]["cvss_base"] = vuln.find("CVSS").find("BASE").text
			vuln_kb_dict[qid]["cvss_temporal"] = vuln.find("CVSS").find("TEMPORAL").text
			vuln_kb_dict[qid]["cvss_access_vector"] = vuln.find("CVSS").find("ACCESS").find("VECTOR").text
			vuln_kb_dict[qid]["cvss_access_complexity"] = vuln.find("CVSS").find("ACCESS").find("COMPLEXITY").text
		except (AttributeError):
			pass

	return vuln_kb_dict

def parseVuln(vuln_report_filename, kb_dict={}):
	host_list = []
	final_report = []
	event_header = ""
	event_string = ""

	tree = et.parse(vuln_report_filename)
	root  = tree.getroot()
	report_datetime = root[1][0].text

	for host in root[1][1]:
		host_list.append(host)

	ldap_status = ldapConnect()
	for host in host_list:	
		# event_header is composed of the core attributes associated with the host
		# that should be part of each vulnerability event such as:
		# IP address, DNS name, OS, OS_CPE, AD OU ...and more.
		event_header = 'datetime="%s" ' % report_datetime
		# Parse first layer of child tags minus last two elements.
		"""
		[<Element 'ID' at 0x7fab39c17110>,
		 <Element 'IP' at 0x7fab39c17150>,
		 <Element 'TRACKING_METHOD' at 0x7fab39c171d0>,
		 <Element 'OS' at 0x7fab39c17210>,
		 <Element 'OS_CPE' at 0x7fab39c17250>,
		 <Element 'DNS' at 0x7fab39c17290>,
		 <Element 'NETBIOS' at 0x7fab39c172d0>,
		 <Element 'LAST_SCAN_DATETIME' at 0x7fab39c17310>,
		 <Element 'LAST_VM_SCANNED_DATE' at 0x7fab39c173d0>,
		 <Element 'LAST_VM_SCANNED_DURATION' at 0x7fab39c17490>,
		 <Element 'LAST_VM_AUTH_SCANNED_DATE' at 0x7fab39c17510>,
		 <Element 'LAST_VM_AUTH_SCANNED_DURATION' at 0x7fab39c17590>,
		 <Element 'TAGS' at 0x7fab39c175d0>,
		 <Element 'DETECTION_LIST' at 0x7fab39c17bd0>]
		 """
		host_child_list = zip([child.tag for child in host.getchildren()], [child.text.strip() for child in host.getchildren() if child.text])
		host_child_list = [n for n in host_child_list if n[1]]
		for item in host_child_list:
			event_header += '%s="%s" ' % tuple([i.replace("\"", "'").lower() for i in item])

		# Perform LDAP lookup for AD OU info.
		try:
			dns_name = host.find("DNS").text
		except (AttributeError):
			print("Error: DNS name for host IP [%s] not found." % host.find("IP").text)
			dns_name = ""

		if dns_name and ldap_status:
			ad_ou = "none"
			# Perform LDAP lookup.
			ldap_obj = ldapSearch("cn=%s" % dns_name)
			# Normalize the output
			if ldap_obj:
				try:
					split_ad_ou = ldap_obj[0][0][0].replace("OU=", "").split(",")[1:-3]
					split_ad_ou.reverse()
					ad_ou = "/".join(split_ad_ou)
				except (IndexError):
					print("Error: ldap_obj\n%s" % ldap_obj)
			event_header += 'ad_ou="%s" ' % ad_ou

		else:
			print("Error: Something went wrong with LDAP AD OU lookup enrichment. dns_name='%s' LDAP Connection='%s'\n" % (dns_name, ldap_status))

		# Parse first layer of child tags skipped from previous logic.
		host_last_child_tags = host.getchildren()[-2:]
		for host_tag in host_last_child_tags:
			for sub_tag in [item.getchildren() for item in host_tag.getchildren()]:
				# TAG and DETECTION_LIST
				if "TAG_ID" in str(sub_tag):
					event_header += '%s="%s" ' % tuple([x.text.replace("\"", "'").lower() for x in sub_tag])
				else:
					temp_list = []
					event_string = ""
					# detection_list_item should be the sub_tags under the <DETECTION> tags (i.e. QID, Type, Severity).
					for detection_list_item in zip([x.tag for x in sub_tag],  [x.text for x in sub_tag]):
						k,v = detection_list_item[0], detection_list_item[1]
						if k == "RESULTS": 
							# Rename this object to ensure sorting will
							# push it to the bottom of the list.
							detection_list_item = ("x_results", v)
						elif k == "QID":
							for line in kb_dict[v].keys():
								# Construct template string to unwrap plugin information from kb_dict.	
								template_str = ""
								# The Qualys 'solution' fields can be super long (over 30,000 chars).
								# Moving to the bottom of the list to curb truncation.
								if line == "solution":	
									template_str += '%s="{%s}" ' % ("z_solution", line)
								else:
									template_str += '%s="{%s}" ' % (line.lower(), line)

								temp_list.append(template_str.format(**kb_dict[v]))

						temp_list.append('%s="%s" ' % (detection_list_item[0].lower(), detection_list_item[1].replace("\"", "'")))

					# Sorting the list will ensure 'x_results' is at the bottom.
					temp_list = sorted(temp_list)	
					event_string = event_header + " ".join(temp_list) + "\r\r\r\r"
					final_report.append(event_string)
					if debug:
						print event_string
	return final_report

def writeOutReport(report_obj, output_filename):
	report_out = open(output_filename, "wa")
	for line in report_obj:
		try:
			report_out.write(line.encode("utf-8"))
		except:
			print("Error UTF-8 encoding the following line:\n%s" % line)

	report_out.close()
	print("Writing file [%s] is complete." % output_filename)

def main():
	kb_dict = {}

	args = parser.parse_args()

	# First parse the knowledge base XML containing vuln "plugin" info.
	if args.kb_report:
		kb_dict = parseKB(args.kb_report)
	else:
		print("No kb_report argument provided. Exiting.")
		exit()
	# Next parse the actual vulnerability report XML 
	# and enrich with previously acquired KB data.
	if args.vuln_report:
		final_report = parseVuln(args.vuln_report, kb_dict)
	else:
		print("No vuln_report argument provided. Exiting.")
		exit()
	# Finally write the parsed report into a file.
	if final_report:
		output_file = "parsed-report-%s.qualys" % int(time.time())
		if args.output_file:
			output_file = args.output_file
		writeOutReport(final_report, output_file)

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()
