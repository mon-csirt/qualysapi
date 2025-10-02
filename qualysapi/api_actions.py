import logging
import time
from urllib import parse as urlparse
import re
# from lxml import objectify
import xml.etree.ElementTree as ET
from qualysapi.api_objects import *
from qualysapi import connector
#Globals
child_tags_list = None
logger = logging.getLogger(__name__)
class QGActions:
    def ruleValidator(self, rule_type: str, rule_body: str):
        #TODO: validator for some of the rule types
        match rule_type:
            case 'network_range':
                #IP range validation
                print(rule_body)
            case 'gav':
                #idk honestly, but somehow i can i guess???
                print(rule_body)
            case 'asset_search':
                #this needs to be xml ugh
                print(rule_body)
            
            
    def getHost(self, host_name=None, host_id=None, verbose=False):
        if verbose:
            call = 'rest/2.0/get/am/asset'
            parameters = host_id
            #TODO: implement verbose retrieval
        else:
            call = "search/am/asset"
            parameters = f"""<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><filters><Criteria field="name" operator="CONTAINS">{host_name}</Criteria></filters></ServiceRequest>"""
            hostData = ET.fromstring(self.request(api_call=call,http_method="POST",data=parameters,api_version="gav").encode("utf-8"))
            # hostData = hostData.HOST_LIST.HOST
            tree =hostData.find('data')
            for item in tree.findall('Asset'):
                asset_id = item.find("id").text if item.find('id') is not None else None
                item_data = {}
                item_data["id"] = item.find("id").text if item.find('id') is not None else None
                item_data["name"] = item.find("name").text if item.find('name') is not None else None
                # asset_name=item_data["name"]
                item_data["created"] = item.find("created").text if item.find('created') is not None else None
                item_data["modified"] = item.find("modified").text if item.find('modified') is not None else None
                item_data["type"] = item.find("type").text if item.find('type') is not None else None
                item_data["has_tags"] = item.find('tags') if item.find('tags') is not None else None
                if item_data['has_tags'] is not None:
                    self.host_tags = []
                    for children in tree.iter('tags'):
                        for tags in children.iter('list'):
                            for tag in tags.iter('TagSimple'):
                                single_tag = tag.find('id').text if tag.find('id') is not None else None
                                if single_tag is not None:
                                    self.host_tags.append(self.getTag(id=single_tag))
                    return Host(
                        item_data["name"],
                        item_data["id"],
                        item_data["type"],
                        item_data["created"],
                        item_data["modified"],
                        tags=self.host_tags
                    )
            return Host(
                item_data["name"],
                item_data["id"],
                item_data["type"],
                item_data["created"],
                item_data["modified"],
            )

    def listHosts(
        self,
        ips=None,
        tags=None,
        os_pattern=None,
        tag_set_exclude=None,
        id_min=None,
        detailed=False,
        echo_request=None,
        limit=100,
    ):

        call = "/api/2.0/fo/asset/host/"
        parameters = {"action": "list", "truncation_limit": str(limit)}
        if detailed:
            parameters["details"] = "All/AGs"
        if tag_set_exclude:
            parameters["tag_set_exclude"] = tags
        if id_min:
            parameters["id_min"] = str(id_min)
        if ips:
            parameters["ips"] = str(ips)
        if tags:
            parameters["use_tags"] = "1"
            parameters["tag_set_by"] = "name"
            parameters["tag_set_include"] = tags
            parameters["show_tags"] = "1"
        if os_pattern:
            parameters["os_pattern"] = os_pattern
        if echo_request:
            parameters["echo_request"] = echo_request

        hostData = objectify.fromstring(self.request(call, parameters).encode("utf-8"))
        hostArray = []
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            hostArray.append(
                Host(
                    host.find("DNS"),
                    host.find("ID"),
                    host.find("IP"),
                    host.find("LAST_VULN_SCAN_DATETIME"),
                    host.find("NETBIOS"),
                    host.find("OS"),
                    host.find("TRACKING_METHOD"),
                )
            )

        return hostArray

    def getHostRange(self, start, end):
        call = "/api/2.0/fo/asset/host/"
        parameters = {"action": "list", "ips": f"{start}-{end}"}
        hostData = objectify.fromstring(self.request(call, parameters).encode("utf-8"))
        hostArray = []
        for host in hostData.RESPONSE.HOST_LIST.HOST:
            hostArray.append(
                Host(
                    host.find("DNS"),
                    host.find("ID"),
                    host.find("IP"),
                    host.find("LAST_VULN_SCAN_DATETIME"),
                    host.find("NETBIOS"),
                    host.find("OS"),
                    host.find("TRACKING_METHOD"),
                )
            )

        return hostArray

    def listVirtualHosts(self, ip=None, port=None):
        call = "/api/2.0/fo/asset/vhost/"
        parameters = {"action": "list", "ip": ip, "port": port}
        hostsData = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
        hosts = [
            VirtualHost(
                hostData.find("FQDN"),
                hostData.find("IP"),
                hostData.find("NETWORK_ID"),
                hostData.find("PORT"),
            )
            for hostData in list(hostsData.VIRTUAL_HOST_LIST.VIRTUAL_HOST)
        ]
        return hosts

    def createVirtualHost(self, fqdn, ip, port):
        call = "/api/2.0/fo/asset/vhost/"
        parameters = {"action": "create", "fqdn": fqdn, "ip": ip, "port": port}
        res = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
        code = getattr(res, "CODE", "")
        logging.debug("%s %s %s", res.DATETIME, code, res.TEXT)
        return code, res

    def deleteVirtualHost(self, ip, port):
        call = "/api/2.0/fo/asset/vhost/"
        parameters = {"action": "delete", "ip": ip, "port": port}
        res = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
        code = getattr(res, "CODE", "")
        logging.debug("%s %s %s", res.DATETIME, code, res.TEXT)
        return code, res

    def listAssetGroups(self, groupName=""):
        call = "asset_group_list.php"
        if groupName == "":
            agData = objectify.fromstring(self.request(call).encode("utf-8"))
        else:
            agData = objectify.fromstring(
                self.request(call, f"title={groupName}").encode("utf-8")
            )

        groupsArray = []
        for group in agData.ASSET_GROUP:
            scanipsArray = []
            scandnsArray = []
            scannersArray = []
            try:
                for scanip in group.SCANIPS.IP:
                    scanipsArray.append(scanip)
            except AttributeError:
                scanipsArray = []  # No IPs defined to scan.

            try:
                for scanner in group.SCANNER_APPLIANCES.SCANNER_APPLIANCE:
                    scannersArray.append(scanner.SCANNER_APPLIANCE_NAME)
            except AttributeError:
                scannersArray = []  # No scanner appliances defined for this group.

            try:
                for dnsName in group.SCANDNS.DNS:
                    scandnsArray.append(dnsName)
            except AttributeError:
                scandnsArray = []  # No DNS names assigned to group.

            groupsArray.append(
                AssetGroup(
                    group.find("BUSINESS_IMPACT"),
                    group.find("ID"),
                    group.find("LAST_UPDATE"),
                    scanipsArray,
                    scandnsArray,
                    scannersArray,
                    group.find("TITLE"),
                )
            )

        return groupsArray

    def listReportTemplates(self):
        call = "report_template_list.php"
        rtData = objectify.fromstring(self.request(call).encode("utf-8"))
        templatesArray = []

        for template in rtData.REPORT_TEMPLATE:
            templatesArray.append(
                ReportTemplate(
                    template.find("GLOBAL"),
                    template.find("ID"),
                    template.find("LAST_UPDATE"),
                    template.find("TEMPLATE_TYPE"),
                    template.find("TITLE"),
                    template.find("TYPE"),
                    template.find("USER"),
                )
            )

        return templatesArray

    def listReports(self, id=0):
        call = "/api/2.0/fo/report"
        max_retries = 10
        if id == 0:
            parameters = {"action": "list"}

            repData = objectify.fromstring(
                self.request(call, parameters).encode("utf-8")
            ).RESPONSE
            reportsArray = []
            if repData.find("REPORT_LIST"):
                while repData.find("REPORT_LIST") is None and max_retries > 0:
                    max_retries = max_retries - 1
                    time.sleep(30)
                    qualys_resp = self.request(call, parameters).encode("utf-8")
                    logging.info("QUALYS_REPONSE " + str(qualys_resp))
                    repData = objectify.fromstring(qualys_resp).RESPONSE
            else:
                logging.info("There are no reports")
                return []

            if max_retries <= 0:
                logging.info("Report Listing not successful")
                return None

            for report in repData.REPORT_LIST.REPORT:
                reportsArray.append(
                    Report(
                        report.find("EXPIRATION_DATETIME"),
                        report.find("ID"),
                        report.find("LAUNCH_DATETIME"),
                        report.find("OUTPUT_FORMAT"),
                        report.find("SIZE"),
                        report.find("STATUS"),
                        report.find("TYPE"),
                        report.find("USER_LOGIN"),
                        report.find("TITLE"),
                    )
                )

            return reportsArray

        else:
            parameters = {"action": "list", "id": id}
            qualys_resp = self.request(call, parameters).encode("utf-8")

            repData_debug = objectify.fromstring(qualys_resp).RESPONSE
            while repData_debug.find("REPORT_LIST") is None and max_retries > 0:
                max_retries = max_retries - 1
                time.sleep(30)
                qualys_resp = self.request(call, parameters).encode("utf-8")
                logging.info("QUALYS_REPONSE " + str(qualys_resp))
                repData_debug = objectify.fromstring(qualys_resp).RESPONSE

            if max_retries <= 0:
                logging.info("Report Listing not successful")
                return None
            repData = objectify.fromstring(
                self.request(call, parameters).encode("utf-8")
            ).RESPONSE.REPORT_LIST.REPORT

            return Report(
                repData.find("EXPIRATION_DATETIME"),
                repData.find("ID"),
                repData.find("LAUNCH_DATETIME"),
                repData.find("OUTPUT_FORMAT"),
                repData.find("SIZE"),
                repData.find("STATUS"),
                repData.find("TYPE"),
                repData.find("USER_LOGIN"),
                repData.find("TITLE"),
            )

    def launchReport(
        self,
        template_id,
        output_format,
        report_title=None,
        echo_request=0,
        report_type=None,
        use_tags=None,
        tag_set_include=None,
        tag_set_by=None,
        tag_set_exclude=None,
        tag_include_selector=None,
        max_retries=3,
    ):
        call = "/api/2.0/fo/report"
        parameters = {
            "action": "launch",
            "template_id": template_id,
            "output_format": output_format,
        }
        if report_title:
            parameters["report_title"] = report_title
        if echo_request:
            parameters["echo_request"] = echo_request
        if report_type:
            parameters["report_type"] = report_type
        if use_tags:
            if use_tags == 0 or use_tags == 1:
                parameters["use_tags"] = use_tags
            else:
                raise ValueError("use_tags must be 0 or 1")
        if tag_set_include:
            parameters["tag_set_include"] = tag_set_include
        if tag_set_exclude:
            parameters["tag_set_exclude"] = tag_set_exclude
        if tag_set_by:
            if tag_set_by == "id" or tag_set_by == "name":
                parameters["tag_set_by"] = tag_set_by
            else:
                raise ValueError("tag_set_by must be id or name")
        if tag_include_selector:
            if tag_include_selector in ('any', 'all'):
                parameters["tag_include_selector"] = tag_include_selector
            else:
                raise ValueError("use_tags must be 'any' or 'all'")

        repData = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
        while (
            repData.find("TEXT")
            == "Max number of allowed reports already running. Please try again later."
            and max_retries > 0
        ):
            max_retries = max_retries - 1
            time.sleep(30)
            repData = objectify.fromstring(
                self.request(call, parameters).encode("utf-8")
            ).RESPONSE
            logging.info(
                "Max number of allowed reports already running. %s attempts left.", max_retries
            )

        if repData.find("TEXT") == "New report launched":
            report_id = repData.find("ITEM_LIST").find("ITEM").find("VALUE")
            return report_id.pyval, repData.find("TEXT")
        else:
            logging.warning(repData.find("TEXT"))
            return -1, repData.find("TEXT")

    def downloadReport(self, report_id, echo_request=0):
        call = "/api/2.0/fo/report"
        parameters = {
            "action": "fetch",
            "id": report_id,
        }
        if echo_request:
            parameters["echo_request"] = echo_request

        return self.request(call, parameters)

    def notScannedSince(self, days):
        call = "/api/2.0/fo/asset/host/"
        parameters = {"action": "list", "details": "All"}
        hostArray = []
        today = datetime.date.today()
        hasNextPage = True
        while hasNextPage:
            hostData = objectify.fromstring(self.request(call, parameters).encode("utf-8"))
            for host in hostData.RESPONSE.HOST_LIST.HOST:
                if host.find("LAST_VULN_SCAN_DATETIME"):
                    last_scan = str(host.LAST_VULN_SCAN_DATETIME).split("T")[0]
                    last_scan = datetime.date(
                        int(last_scan.split("-")[0]),
                        int(last_scan.split("-")[1]),
                        int(last_scan.split("-")[2]),
                    )
                    if (today - last_scan).days >= days:
                        hostArray.append(
                            Host(
                                host.find("DNS"),
                                host.find("ID"),
                                host.find("IP"),
                                host.find("LAST_VULN_SCAN_DATETIME"),
                                host.find("NETBIOS"),
                                host.find("OS"),
                                host.find("TRACKING_METHOD"),
                            )
                        )
            try:
                id_min = dict(
                    urlparse.parse_qsl(
                        urlparse.urlparse(str(hostData.RESPONSE.WARNING.URL)).query
                    )
                )["id_min"]
                parameters["id_min"] = id_min
            except:
                hasNextPage = False

        return hostArray

    def addIP(self, ips, vmpc):
        # 'ips' parameter accepts comma-separated list of IP addresses.
        # 'vmpc' parameter accepts 'vm', 'pc', or 'both'. (Vulnerability Managment, Policy Compliance, or both)
        call = "/api/2.0/fo/asset/ip/"
        enablevm = 1
        enablepc = 0
        if vmpc == "pc":
            enablevm = 0
            enablepc = 1
        elif vmpc == "both":
            enablevm = 1
            enablepc = 1

        parameters = {"action": "add", "ips": ips, "enable_vm": enablevm, "enable_pc": enablepc}
        self.request(call, parameters)

    def listScans(self, launched_after="", state="", target="", type="", user_login=""):
        # 'launched_after' parameter accepts a date in the format: YYYY-MM-DD
        # 'state' parameter accepts "Running", "Paused", "Canceled", "Finished", "Error", "Queued", and "Loading".
        # 'title' parameter accepts a string
        # 'type' parameter accepts "On-Demand", and "Scheduled".
        # 'user_login' parameter accepts a user name (string)
        call = "/api/2.0/fo/scan/"
        parameters = {"action": "list", "show_ags": 1, "show_op": 1, "show_status": 1}
        if launched_after != "":
            parameters["launched_after_datetime"] = launched_after

        if state != "":
            parameters["state"] = state

        if target != "":
            parameters["target"] = target

        if type != "":
            parameters["type"] = type

        if user_login != "":
            parameters["user_login"] = user_login

        scanlist = objectify.fromstring(self.request(call, parameters).encode("utf-8"))
        scanArray = []
        for scan in scanlist.RESPONSE.SCAN_LIST.SCAN:
            try:
                agList = []
                for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                    agList.append(ag)
            except AttributeError:
                agList = []

            scanArray.append(
                Scan(
                    agList,
                    scan.find("DURATION"),
                    scan.find("LAUNCH_DATETIME"),
                    scan.find("OPTION_PROFILE.TITLE"),
                    scan.find("PROCESSED"),
                    scan.find("REF"),
                    scan.find("STATUS"),
                    scan.find("TARGET"),
                    scan.find("TITLE"),
                    scan.find("TYPE"),
                    scan.find("USER_LOGIN"),
                )
            )

        return scanArray

#   don't need this anymore I reckon  
#   def listChildTags(self, tag_name=None, tag_id=None, filename=None):
#         if tag_id:
#             files = (
#                 """<ServiceRequest>
# <filters>
# <Criteria field="id" operator="EQUALS">"""
#                 + tag_id
#                 + """</Criteria>
# </filters>
# </ServiceRequest>"""
#             )
#         elif filename:
#             files = open(filename, "rb").read()
#         elif tag_name:
#             files = (
#                 """<ServiceRequest>
# <filters>
# <Criteria field="name" operator="EQUALS">"""
#                 + tag_name
#                 + """</Criteria>
# </filters>
# </ServiceRequest>"""
#             ).encode("ascii", "ignore")

#         call = "/qps/rest/2.0/search/am/tag"
#         parameters = files
#         response = objectify.fromstring(
#             self.request(call, parameters, api_version=2, http_method="post").encode("utf-8")
#         )
#         childs = list()
#         for child in response.getchildren()[3][0].Tag.children.list.getchildren():
#             childs.append(child.getchildren())

#         return childs

    def launchScan(self, title, option_title, iscanner_name, asset_groups="", ip=""):
        # TODO: Add ability to scan by tag.
        call = "/api/2.0/fo/scan/"
        parameters = {
            "action": "launch",
            "scan_title": title,
            "option_title": option_title,
            "iscanner_name": iscanner_name,
            "ip": ip,
            "asset_groups": asset_groups,
        }
        if ip == "":
            parameters.pop("ip")

        if asset_groups == "":
            parameters.pop("asset_groups")

        scan_ref = (
            objectify.fromstring(self.request(call, parameters).encode("utf-8"))
            .RESPONSE.ITEM_LIST.ITEM[1]
            .VALUE
        )

        call = "/api/2.0/fo/scan/"
        parameters = {
            "action": "list",
            "scan_ref": scan_ref,
            "show_status": 1,
            "show_ags": 1,
            "show_op": 1,
        }

        scan = objectify.fromstring(
            self.request(call, parameters).encode("utf-8")
        ).RESPONSE.SCAN_LIST.SCAN
        try:
            agList = []
            for ag in scan.ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE:
                agList.append(ag)
        except AttributeError:
            agList = []

        return Scan(
            agList,
            scan.find("DURATION"),
            scan.find("LAUNCH_DATETIME"),
            scan.find("OPTION_PROFILE.TITLE"),
            scan.find("PROCESSED"),
            scan.find("REF"),
            scan.find("STATUS"),
            scan.find("TARGET"),
            scan.find("TITLE"),
            scan.find("TYPE"),
            scan.find("USER_LOGIN"),
        )


    def deleteReport(self, id):
        call = "/api/2.0/fo/report/"
        parameters = {"action": "delete", "id": id}
        res = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
        code = getattr(res, "CODE", "")

        max_retries = 7
        while res.TEXT != 'Report deleted' and max_retries > 0:
            max_retries = max_retries - 1
            time.sleep(40)
            res = objectify.fromstring(self.request(call, parameters).encode("utf-8")).RESPONSE
            code = getattr(res, "CODE", "")
            logging.info("QUALYS_REPONSE " + str(res.TEXT))

        if max_retries <= 0:
            logging.info("%s %s", code, res.TEXT)
            return None

        logging.debug("%s %s %s", res.DATETIME, code, res.TEXT)
        return code, res

    def listAppliances(self):
        call = "/api/2.0/fo/appliance/"
        parameters = {
            "action": "list"
        }

        scanner_data = objectify.fromstring(self.request(call, parameters).encode("utf-8"))
        scanner_array = []
        for scanner in scanner_data.RESPONSE.APPLIANCE_LIST.APPLIANCE:
            scanner_array.append(
                Scanner(
                    scanner.find("ID"),
                    scanner.find("UUID"),
                    scanner.find("NAME"),
                    scanner.find("NETWORK_ID"),
                    scanner.find("SOFTWARE_VERSION"),
                    scanner.find("RUNNING_SLICES_COUNT"),
                    scanner.find("RUNNING_SCAN_COUNT"),
                    scanner.find("STATUS")
                )
            )

        return scanner_array

    def getTag(self, tag_name: str | None = None,tag_id: int | None = None):
        #TODO: fix recursion where multiple layers of child tags exist
        #TODO: enable searching by all types of search parameters through arguments passed
        call = "search/am/tag"
        if (tag_name is not None) and (tag_id is not None):
            logger.error('Error: unable to search, both tag name and id provided')
            return None
        else:
            parameters= f"""<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><filters><Criteria field="name" operator="EQUALS">{tag_name}</Criteria></filters></ServiceRequest>""" if tag_name is not None else f"""<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><filters><Criteria field="id" operator="EQUALS">{tag_id}</Criteria></filters></ServiceRequest>"""
        tagData = ET.fromstring(self.request(api_call=call,http_method="POST",data=parameters,api_version="gav").encode("utf-8"))
        items_found = int(tagData.find('count').text)
        if items_found == 1:
            tree =tagData.find('data')
            for item in tree.findall('Tag'):
                item_data = {}
                item_data["id"] = int(item.find("id").text) if item.find('id') is not None else None
                item_data["name"] = str(item.find("name").text) if item.find('name') is not None else None
                item_data["created"] = str(item.find("created").text) if item.find('created') is not None else None
                item_data["modified"] = str(item.find("modified").text) if item.find('modified') is not None else None
                item_data["colour"] = str(item.find("color").text) if item.find('color') is not None else None
                item_data['description'] = str(item.find('description').text) if item.find('description') is not None else None
                item_data['has_children'] = True if item.find('children') is not None else False
                item_data['rule_type'] = str(item.find('ruleType').text) if item.find('ruleType') is not None else None
                item_data['rule_value'] = str(item.find('ruleText').text) if item.find('ruleText') is not None else None
                item_data['criticality'] = int(item.find('criticalityScore').text) if item.find('criticalityScore') is not None else None
            if item_data['has_children']:
                self.child_tags_list = []
                for list in tree.iter('children'):
                    for items in list.iter('list'):
                        for tags in items.iter('TagSimple'):
                            single_tag = int(tags.find('id').text) if item.find('id') is not None else None
                            if single_tag is not None:
                                tag = self.getTag(tag_id=single_tag)
                                self.child_tags_list.append(tag)
                return Tag(
                    name=item_data["name"],
                    id=item_data["id"],
                    colour=item_data["colour"],
                    created=item_data["created"],
                    modified=item_data["modified"],
                    description=item_data['description'],
                    child_tags=self.child_tags_list,
                    criticality=item_data['criticality'],
                    rule_type=item_data['rule_type'],
                    dynamic_rule=item_data['rule_value'],
                )
            else:
                return Tag(
                    name=item_data["name"],
                    id=item_data["id"],
                    colour=item_data["colour"],
                    created=item_data["created"],
                    modified=item_data["modified"],
                    description=item_data['description'],
                    criticality=item_data['criticality'],
                    rule_type=item_data['rule_type'],
                    dynamic_rule=item_data['rule_value'],
            )
        if items_found > 1:
            #TODO: return multiple tags for name-based search?
            value = str(tag_id) if tag_id is not None else tag_name
            logger.warning(f'Warning: multiple results returned for tag: {value}')
            return None #for now...
        if items_found < 1:
            value = str(tag_id) if tag_id is not None else tag_name
            logger.warning(f'Warning: unable to find tag: {value}')
            return None

    def editTag(self, tag: Tag, name: str | None = None, colour: str | None = None, criticality: int | None = None,rule_type: str | None = None,rule_text: str | None = None,child_tags: list | None = None,child_tag_action: str | None = None,description: str | None = None):
        #TODO: allow passing attributes as dict of attributes?
        #TODO: add additional editable attributes to function
        call = f'update/am/tag/{str(tag.id)}'
        parameters = """<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><data><Tag>"""
        if colour is not None:
            colour_validation = re.compile(r'#([A-Fa-f0-9]){6}')
            if not colour_validation.fullmatch(colour):
                logger.error(f'Error: colour is not valid hex code: {colour}')
                return None
            else:
                parameters += f"""<color>{colour}</color>"""
        if name is not None:
            parameters +=f"""<name>{name}</name>"""
        if criticality is not None and int(criticality) < 6 and int(criticality) > 0:
            parameters +=f"""<criticalityScore>{int(criticality)}</criticalityScore>"""
        if description is not None:
            parameters += f"""<description>{description}</description>"""
        parameters += """</Tag></data></ServiceRequest>"""
        tagData = ET.fromstring(self.request(api_call=call,http_method="POST",data=parameters,api_version="gav").encode("utf-8"))
        for item in tagData.findall('responseCode'):
            if item.text == 'SUCCESS':
                tree =tagData.find('data')
                tag_id = None
                for item in tree.findall('Tag'):
                    tag_id = item.find('id').text if item.find('id') is not None else None
                return self.getTag(tag_id=tag_id) #required as returned tag on success does not contain all necessary attributes
            else:
                logger.error('Error: Tag failed to update')
                return None

    def createTag(self, name: str, colour: str | None = None, criticality: int | None = None,rule_type: str | None = None,rule_text: str | None = None,child_tags: list | None = None,child_tag_action: str | None = None,description: str | None = None):
        #TODO: Validation of creation
        #TODO: ability to create tags with child tags, dynamic rules
        #TODO: allow passing attributes for tag as dict of attribs
        call = 'create/am/tag'
        colour_validation = re.compile(r'#([A-Fa-f0-9]){6}')
        if colour is None:
            colour = "#FFFFFF"
        if not colour_validation.fullmatch(colour):
            logger.error(f'Error: colour provided is not valid hex code: {colour}')
            return None
        parameters = f"""<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><data><Tag><name>{name}</name>"""
        if criticality is not None and int(criticality) < 6 and int(criticality) > 0:
            parameters +=f"""<criticalityScore>{int(criticality)}</criticalityScore>"""
        if description is not None:
            parameters += f"""<description>{description}</description>"""
        parameters += f"""</Tag></data></ServiceRequest>"""

        tagData = ET.fromstring(self.request(api_call=call,http_method="POST",data=parameters,api_version="gav").encode("utf-8"))
        for item in tagData.findall('responseCode'):
            if item.text == 'SUCCESS':
                tree =tagData.find('data')
                for item in tree.findall('Tag'):
                    item_data = {}
                    item_data["id"] = item.find("id").text if item.find('id') is not None else None
                    item_data["name"] = item.find("name").text if item.find('name') is not None else None
                    item_data["created"] = item.find("created").text if item.find('created') is not None else None
                    item_data["modified"] = item.find("modified").text if item.find('modified') is not None else None
                    item_data["colour"] = item.find("color").text if item.find('color') is not None else None
                return Tag(
                    item_data["name"],
                    item_data["id"],
                    item_data["colour"],
                    item_data["created"],
                    item_data["modified"],
                )
            else:
                logger.error(f'Error: unable to create tag: {name}')
                return None

    def deleteTag(self, tag: Tag):
        # delete a tag given a tag object
        # input: Tag object
        # output: boolean denoting status of deletion attempt
        call = f'delete/am/tag/{str(tag.id)}'
        parameters = None
        if self.getTag(tag.name) is not None:
            deletedTagData = ET.fromstring(self.request(api_call=call,http_method="POST",data=parameters,api_version="gav").encode('utf-8'))
            for item in deletedTagData.findall('responseCode'):
                if item.text == 'SUCCESS':
                    return True
                else:
                    logger.error(f'Error: deletion failed for tag {tag.name}')
                    return False
        else:
            return False