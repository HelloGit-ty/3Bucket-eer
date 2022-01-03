import google.oauth2.credentials
from google.cloud import storage
from google.oauth2 import service_account
import slack_alerts
import argparse
import os
import requests
import datetime
from termcolor import colored

def driver(argz):
    if argz.Bexists is not None and argz.Blist is False and argz.Olist is False and argz.FA is None:
        buck_ex(argz.Bexists, argz.out)
    if argz.Oexists is not None and argz.Blist is False and argz.Olist is False and argz.FA is None:
        buck_name = input("Enter the name of the bucket whose objects you want to search for.\nNOTE-> If you do not have any bucket names available try using the --Bexists arg to check for the exisence of buckets from a file.\nBucket Name--> ")
        obj_ex(argz.Oexists, buck_name, argz.out)
    if argz.auth is not None and argz.Blist is False and argz.Olist is False and argz.FA is None:
        print("Enter a flag! Exiting...")
        exit(1)
    if argz.serv is not None and argz.Blist is False and argz.Olist is False and argz.FA is None:
        print("Enter a flag! Exiting...")
        exit(1)
    if argz.auth is not None and argz.Blist is True and argz.Olist is False and argz.FA is None:
        project = input("Enter the GCP project name for which you want to browse the cloud storage--> ")
        credentials = google.oauth2.credentials.Credentials(argz.auth.rstrip())
        buck_list(credentials, argz.out, project)
    if argz.serv is not None and argz.Blist is True and argz.Olist is False and argz.FA is None:
        project = input("Enter the GCP project name for which you want to browse the cloud storage--> ")
        credentials = service_account.Credentials.from_service_account_file(argz.serv)
        buck_list(credentials, argz.out, project)
    if argz.auth is not None and argz.Blist is False and argz.Olist is True and argz.FA is None:
        project = input("Enter the GCP project name for which you want to browse the cloud storage--> ")
        credentials = google.oauth2.credentials.Credentials(argz.auth.rstrip())
        obj_list(credentials, argz.out, project)
    if argz.serv is not None and argz.Blist is False and argz.Olist is True and argz.FA is None:
        project = input("Enter the GCP project name for which you want to browse the cloud storage--> ")
        credentials = service_account.Credentials.from_service_account_file(argz.serv)
        obj_list(credentials, argz.out, project)
    if argz.auth is not None and argz.Blist is False and argz.Olist is False and argz.FA is not None and argz.White is not None and argz.webhook is not None:
        credentials = google.oauth2.credentials.Credentials(argz.auth.rstrip())
        auto(credentials, str(argz.FA), str(argz.White), str(argz.webhook))
    if argz.serv is not None and argz.Blist is False and argz.Olist is False and argz.FA is not None and argz.White is not None and argz.webhook is not None:
        credentials = service_account.Credentials.from_service_account_file(argz.serv)
        auto(credentials, str(argz.FA), str(argz.White), str(argz.webhook))

def buck_ex(Bexists, out):
    outfile = []
    if "/" in str(Bexists) or "\\" in str(Bexists):
        name, ext = os.path.splitext(str(Bexists))
        if ext == ".txt" and os.path.isfile(str(Bexists)):
            try:
                with open(str(Bexists), 'r') as BFile:
                    for buckets in BFile.readlines():
                        try:
                            check = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(str(buckets).rstrip()))
                        except requests.exceptions.RequestException as err:
                            raise SystemExit(err)
                        if check.status_code in [400, 404]:
                            str1 = "Bucket {} does not exist!".format(str(buckets).rstrip())
                            outfile.append(str1)
                            text = colored(str1, 'red', attrs=['bold'])
                            print(text)
                        if check.status_code in [500, 502, 503, 504]:
                            str1 = "Internal server error. Try again later!"
                            outfile.append(str1)
                            text = colored(str1, 'white')
                            print(text)
                        if check.status_code == 429:
                            str1 = "You have exceeded the number of API queries!"
                            outfile.append(str1)
                            text = colored(str1, 'white')
                            print(text)
                        if check.status_code == 401:
                            str1 = "Bucket {} exists but you need to provide an authorization header i.e AllAuthenticatedUsers/Authenticated users".format(str(buckets).rstrip())
                            outfile.append(str1)
                            text = colored(str1, 'yellow', attrs=['bold'])
                            print(text)
                        if check.status_code in [200]:
                            str1 = "Bucket {} exists and is completely public i.e ALLUsers".format(str(buckets).rstrip())
                            outfile.append(str1)
                            text = colored(str1, 'green', attrs=['bold'])
                            print(text)
            except FileNotFoundError as err:
                print("The file you entered doesn't exist. Error msg--> ", err, "\n Exiting...")
                exit(-1)
            if out is not None:
                if os.path.exists(str(out)):
                    f_name = input("Enter the output file name without a file extension--> ")
                    out_f = str(out) + f_name + "_result_3B" + ".txt"
                    with open(str(out_f), 'w') as outputz:
                        outputz.writelines(outfile)
                else:
                    print("Path not found!")
                    exit(1)
        else:
            print("The file type is not txt. Exiting...")
            exit(1)
    else:
        if out is not None:
            text = colored("The --out argument is redundant if you are checking the existence of a single bucket! Ignoring the arg...", 'magenta', attrs=['bold'])
            print(text)
        try:
            check = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(str(Bexists)))
        except requests.exceptions.RequestException as err:
            raise SystemExit(err)
        if check.status_code in [400, 404]:
            text = colored("Bucket {} does not exist!".format(Bexists), "red", attrs=['bold'])
            print(text)
        if check.status_code in [500, 502, 503, 504]:
            text = colored("Internal server error. Try again later!", "white")
            print(text)
        if check.status_code == 429:
            text = colored("You have exceeded the number of API queries!", "white")
            print(text)
        if check.status_code == 401:
            text = colored("Bucket {} exists but you need to provide an authorization header i.e AllAuthenticatedUsers/Authenticated Users".format(Bexists), "yellow", attrs=['bold'])
            print(text)
        if check.status_code in [200]:
            text = colored("Bucket {} exists and is completely public i.e ALLUsers".format(Bexists), "green", attrs=['bold'])
            print(text)

def obj_ex(Oexists, Bname, out):
    outfile = []
    if "/" in str(Oexists) or "\\" in str(Oexists):
        name, ext = os.path.splitext(str(Oexists))
        if ext == ".txt" and os.path.isfile(str(Oexists)):
            try:
                with open(str(Oexists), 'r') as OFile:
                    for objects in OFile.readlines():
                        try:
                            check = requests.head('https://storage.googleapis.com/{}/{}'.format(Bname, str(objects).rstrip()))
                        except requests.exceptions.RequestException as err:
                            raise SystemExit(err)
                        if check.status_code in [400, 404]:
                            str1 = "Either bucket {} doesn't exist or Bucket {} exists and is public but object {} does not exist in the bucket!".format(Bname, Bname, str(objects).rstrip())
                            outfile.append(str1)
                            text = colored(str1, 'red', attrs=['bold'])
                            print(text)
                        if check.status_code in [500, 502, 503, 504]:
                            str1 = "Internal server error. Try again later!"
                            outfile.append(str1)
                            text = colored(str1, 'white')
                            print(text)
                        if check.status_code == 429:
                            str1 = "You have exceeded the number of API queries!"
                            outfile.append(str1)
                            text = colored(str1, 'white')
                            print(text)
                        if check.status_code == 403:
                            str1 = "Either the bucket {} has Object-level ACLs set, and the object {} is private or doesn't exist in the bucket, or Bucket {} is private".format(Bname,str(objects).rstrip(),Bname)
                            outfile.append(str1)
                            text = colored(str1, 'yellow', attrs=['bold'])
                            print(text)
                        if check.status_code in [200]:
                            str1 = "Object {} exists in {} and is completely public".format(str(objects).rstrip(), Bname)
                            outfile.append(str1)
                            text = colored(str1, 'green', attrs=['bold'])
                            print(text)
            except FileNotFoundError as err:
                print("The file you entered doesn't exist. Error msg--> ", err, "\n Exiting...")
                exit(-1)
            if out is not None:
                if os.path.exists(str(out)):
                    f_name = input("Enter the output file name without a file extension--> ")
                    out_f = str(out) + f_name + "_result_3B" + ".txt"
                    with open(str(out_f), 'w') as outputz:
                        outputz.writelines(outfile)
                else:
                    print("Path not found!")
                    exit(1)
        else:
            print("The file type is not txt. Exiting...")
            exit(1)
    else:
        if out is not None:
            text = colored("The --out argument is redundant if you are checking the existence of a single bucket! Ignoring the arg...", 'magenta', attrs=['bold'])
            print(text)
        try:
            check = requests.head('https://storage.googleapis.com/{}/{}'.format(Bname, str(Oexists)))
        except requests.exceptions.RequestException as err:
            raise SystemExit(err)
        if check.status_code in [400, 404]:
            str1 = "Either bucket {} doesn't exist or Bucket {} exists and is public but object {} does not exist!".format(Bname, Bname, str(Oexists))
            text = colored(str1, 'red', attrs=['bold'])
            print(text)
        if check.status_code in [500, 502, 503, 504]:
            str1 = "Internal server error. Try again later!"
            text = colored(str1, 'white')
            print(text)
        if check.status_code == 429:
            str1 = "You have exceeded the number of API queries!"
            text = colored(str1, 'white')
            print(text)
        if check.status_code == 403:
            str1 = "Either the bucket {} has Object-level ACLs set, and the object {} is private or doesn't exist, or Bucket {} is private".format(Bname, str(Oexists), Bname)
            text = colored(str1, 'yellow', attrs=['bold'])
            print(text)
        if check.status_code in [200]:
            str1 = "Object {} exists and is completely public".format(str(Oexists))
            text = colored(str1, 'green', attrs=['bold'])
            print(text)

def buck_list(creds, out, project_name):
    outz = []
    flag = 0
    client = storage.Client(project=project_name, credentials=creds)
    buckets = client.list_buckets()
    for buck in buckets:
        meta = client.get_bucket(str(buck.name))
        str1 = f"Name: {meta.name}"
        outz.append(str1)
        print(str1)
        str1 = f"Storage Class: {meta.storage_class}"
        outz.append(str1)
        print(str1)
        str1 = f"Cors: {meta.cors}"
        outz.append(str1)
        print(str1)
        str1 = f"Default KMS Key Name: {meta.default_kms_key_name}"
        outz.append(str1)
        print(str1)
        str1 = f"Retention Effective Time: {meta.retention_policy_effective_time}"
        outz.append(str1)
        print(str1)
        str1 = f"Retention Period: {meta.retention_period}"
        outz.append(str1)
        print(str1)
        str1 = f"Retention Policy Locked: {meta.retention_policy_locked}"
        outz.append(str1)
        print(str1)
        str1 = f"Time Created: {meta.time_created}"
        outz.append(str1)
        print(str1)
        str1 = f"Versioning Enabled: {meta.versioning_enabled}"
        outz.append(str1)
        print(str1)
        if meta.iam_configuration.uniform_bucket_level_access_enabled:
            str1 = "Uniform Access control"
            outz.append(str1)
            print(str1)
        elif meta.iam_configuration.uniform_bucket_level_access_enabled == False:
            str1 = "Fine-grained access control"
            outz.append(str1)
            print(str1)
        else:
            str1 = "Unknown Access control"
            outz.append(str1)
            print(str1)
        pol = client.bucket(str(buck.name))
        policy = pol.get_iam_policy(requested_policy_version=3)
        for binding in policy.bindings:
            if str(binding["members"]) == "{'allUsers'}" or str(binding["members"]) == "{'allAuthenticatedUsers'}":
                flag = 1
                str1 = "This bucket is Public to the internet and the IAM role the user has is {}".format(binding["role"])
                outz.append(str1)
                text = colored(str1, 'red', attrs=['bold'])
                print(text)
            else:
                pass
        if flag != 1:
            str1 = "This bucket is private"
            outz.append(str1)
            print(str1)
        str2 = "\n" + "\n"
        outz.append(str2)
        print(str2)
    if out is not None:
        if os.path.exists(str(out)):
            f_name = input("Enter the output file name without a file extension--> ")
            out_f = str(out) + f_name + "_result_3B" + ".txt"
            with open(str(out_f), 'w') as outputz:
                outputz.writelines(outz)
        else:
            print("Path not found!")
            exit(1)

def obj_list(creds, out, project_name):
    outputz = []
    flag = 0
    client = storage.Client(project=project_name, credentials=creds)
    ch = int(input("1. List all objects under all buckets in the project\n2. List all objects under the specified bucket\nEnter --> "))
    if ch == 1:
        buckets = client.list_buckets()
        for buck in buckets:
            bck = client.bucket(str(buck.name))
            objects = client.list_blobs(str(buck.name))
            meta = client.get_bucket(str(buck.name))
            str2 = "Bucket_name: {}".format(buck.name)
            text = colored(str2, 'white', attrs=['bold'])
            print(text)
            outputz.append(str2)
            for obj in objects:
                blob = bck.get_blob(str(obj.name))
                str1 = "Blob: {}".format(blob.name)
                outputz.append(str1)
                print(str1)
                str1 = "Size: {} bytes".format(blob.size)
                outputz.append(str1)
                print(str1)
                str1 = "Updated: {}".format(blob.updated)
                outputz.append(str1)
                print(str1)
                str1 = "Owner: {}".format(blob.owner)
                outputz.append(str1)
                print(str1)
                str1 = "Cache-control: {}".format(blob.cache_control)
                outputz.append(str1)
                print(str1)
                str1 = "Content-type: {}".format(blob.content_type)
                outputz.append(str1)
                print(str1)
                str1 = "Temporary hold: ", "enabled" if blob.temporary_hold else "disabled"
                outputz.append(str1)
                print(str1)
                str1 = "Event based hold: ", "enabled" if blob.event_based_hold else "disabled"
                outputz.append(str1)
                print(str1)
                if not meta.iam_configuration.uniform_bucket_level_access_enabled:
                    str1 = "ACLs cannot be retrieved for buckets with uniform access"
                    text = colored(str1, 'yellow')
                    outputz.append(str1)
                    print(text)
                elif meta.iam_configuration.uniform_bucket_level_access_enabled:
                    acls = bck.blob(obj.name)
                    for entry in acls.acl:
                        if entry["entity"] == "allUsers" or entry["entity"] == "allAuthenticatedUsers":
                            flag = 1
                            str1 = "Public access is enabled on this object and the permission available is {}".format(entry["role"])
                            outputz.append(str1)
                            text = colored(str1, 'red', attrs=['bold'])
                            print(text)
                        else:
                            pass
                    if flag != 1:
                        str1 = "Object is Private"
                        outputz.append(str1)
                        print(str1)
                str1 = "\n"
                outputz.append(str1)
                print(str1)
            str1 = "\n" + "\n"
            outputz.append(str1)
            print(str1)
    if ch == 2:
        buck_name = input("Enter the bucket name --> ")
        bck = client.bucket(buck_name)
        objects = client.list_blobs(buck_name)
        meta = client.get_bucket(buck_name)
        str2 = "Bucket_name: {}".format(buck_name)
        text = colored(str2, 'white', attrs=['bold'])
        print(text)
        outputz.append(str2)
        for obj in objects:
            blob = bck.get_blob(str(obj.name))
            str1 = "Blob: {}".format(blob.name)
            outputz.append(str1)
            print(str1)
            str1 = "Size: {} bytes".format(blob.size)
            outputz.append(str1)
            print(str1)
            str1 = "Updated: {}".format(blob.updated)
            outputz.append(str1)
            print(str1)
            str1 = "Owner: {}".format(blob.owner)
            outputz.append(str1)
            print(str1)
            str1 = "Cache-control: {}".format(blob.cache_control)
            outputz.append(str1)
            print(str1)
            str1 = "Content-type: {}".format(blob.content_type)
            outputz.append(str1)
            print(str1)
            str1 = "Temporary hold: ", "enabled" if blob.temporary_hold else "disabled"
            outputz.append(str1)
            print(str1)
            str1 = "Event based hold: ", "enabled" if blob.event_based_hold else "disabled"
            outputz.append(str1)
            print(str1)
            if not meta.iam_configuration.uniform_bucket_level_access_enabled:
                str1 = "ACLs cannot be retrieved for buckets with uniform access"
                text = colored(str1, 'yellow')
                outputz.append(str1)
                print(text)
            elif meta.iam_configuration.uniform_bucket_level_access_enabled:
                acls = bck.blob(obj.name)
                for entry in acls.acl:
                    if entry["entity"] == "allUsers" or entry["entity"] == "allAuthenticatedUsers":
                        flag = 1
                        str1 = "Public access is enabled on this object"
                        outputz.append(str1)
                        text = colored(str1, 'red', attrs=['bold'])
                        print(text)
                    else:
                        pass
                if flag != 1:
                    str1 = "Object is Private"
                    outputz.append(str1)
                    print(str1)
            str1 = "\n"
            outputz.append(str1)
            print(str1)
        str1 = "\n" + "\n"
        outputz.append(str1)
        print(str1)
    if out is not None:
        if os.path.exists(str(out)):
            f_name = input("Enter the output file name without a file extension--> ")
            out_f = str(out) + f_name + "_result_3B" + ".txt"
            with open(str(out_f), 'w') as outputz:
                outputz.writelines(outputz)
        else:
            print("Path not found!")
            exit(1)

def auto(creds, project_name, WL, WH):
    ls = []
    slack_al = []
    client = storage.Client(project=project_name, credentials=creds)
    buckets = client.list_buckets()
    if os.path.exists(str(WL)) and os.path.isfile(str(WL)) and str(WL).endswith(".txt"):
        with open(str(WL), 'r') as wlo:
            for names in wlo.readlines():
               ls.append(str(names).rstrip())
        for buck in buckets:
            if buck.name not in ls:
                meta = client.get_bucket(str(buck.name))
                if meta.iam_configuration.uniform_bucket_level_access_enabled:
                    pol = client.bucket(str(buck.name))
                    policy = pol.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        if str(binding["members"]) == "{'allUsers'}" or str(binding["members"]) == "{'allAuthenticatedUsers'}":
                            alert_time = datetime.datetime.now()
                            compose = str(alert_time) + " | " + buck.name + " | " + "Public" + " | " + str(binding["role"]) + " | " + str(binding["members"]) + " | " + str(meta.time_created) + " | " + "https://console.cloud.google.com/storage/browser/{}".format(buck.name)
                            #print(compose)
                            slack_al.append(compose)
                        else:
                            pass
                elif not meta.iam_configuration.uniform_bucket_level_access_enabled:
                    obj = client.list_blobs(buck.name)
                    for blobs in obj:
                        if blobs.name not in ls:
                            blob1 = client.bucket(str(buck.name))
                            x = blob1.get_blob(blobs.name)
                            acls = blob1.blob(blobs.name)
                            for entry in acls.acl:
                                if entry["entity"] == "allUsers" or entry["entity"] == "allAuthenticatedUsers":
                                    alert_time = datetime.datetime.now()
                                    compose = str(alert_time) + " | " + blobs.name + " | " + "Public" + " | " + str(entry["role"]) + " | " + str(entry["entity"]) + " | " + str(x.updated) + " | " + "https://storage.googleapis.com/{}/{}".format(buck.name, blobs.name)
                                    #print(compose)
                                    slack_al.append(compose)
                                else:
                                    pass
            else:
                pass

# Sending the alerts over Slack using custom configured incoming webhooks

        if len(slack_al) > 0:
            c=0
            alert = ""
            alerter = slack_alerts.Alerter(WH)
            heading = "FORMAT :- \nalert time | buck/obj name | public : role : alUsers/allAuthUsers | creation time | link" + "\n\n\n"
            for al in slack_al:
                c = c+1
                alert = alert + str(c) + ". " + al + "\n\n"
            final_alert = heading + alert
            alerter.critical(final_alert)
    else:
        exit(-1)

def cli_help_intf():
    help_msg = "This is the 3Bucket-eer tool, used to scan/enumerate the storage buckets you have in a GCP project and other details about those buckets (public/private, ACLs, regions etc).\nYou can also use this tool in an authenticated manner." + " NOTE:- This tool does not use brute force or wordlists to find out buckets even though you can check out the existence of a bucket/object in an unauthenticated manner considering you already have the name.\nYou must have valid access to the GCP storage services of the project!"
    cli_help = argparse.ArgumentParser(description=help_msg)
    group = cli_help.add_mutually_exclusive_group(required=False)
    group2 = cli_help.add_mutually_exclusive_group(required=False)

    group.add_argument("--Bexists", required=False, default=None, help="Check, unauthenticated, if a bucket exists. Pass the bucket_name/file containing buckets_names. "+"ENTER THE FULL PATH!")
    group.add_argument("--Oexists", required=False, default=None, help="Check, unauthenticated, if a object exists in a particular bucket. Pass the obj_name/file containing obj_names. "+"ENTER THE FULL PATH!")
    group.add_argument("--auth", required=False, default=None, help="Pass your user account access token")
    group.add_argument("--serv", required=False, default=None, help="The path to the JSON file that contains the private key for a GCP service account")
    group2.add_argument("-Blist", required=False, action="store_true", help="List only bucket names and their metadata")
    group2.add_argument("-Olist", required=False, action="store_true", help="List all the obj/s per bucket and metadata")
    cli_help.add_argument("--White", required=False, default=None, help="To pass a whitelist of bucket and object name in a txt file in a list format to be used along with the --FA param.")
    cli_help.add_argument("--webhook", required=False, default=None, help="Custom Webhook URL for slack alerts. To be used along with the --FA param.")
    text = colored("Usage- python3 3Bucket-eer.py --auth access_token --FA GCP_project_name --webhook https://hooks.slack.com/your/URL --white /home/username/Desktop/whitelist.txt", 'yellow', attrs=['bold'])
    group2.add_argument("--FA", required=False, default=None, help="To run the tool in a fully automated manner and send alerts over slack(No STDOUT). {}".format(text))
    cli_help.add_argument("--out", required=False, default=None, help="Pass your path where you wanna create your output file. "+"PLEASE MAKE SURE YOU END THE PATH USING '/'")

    args = cli_help.parse_args()
    driver(args)

if __name__ == "__main__":
    cli_help_intf()
