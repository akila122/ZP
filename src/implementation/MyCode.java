/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;


import code.GuiException;
import static gui.GuiInterfaceV1.reportError;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import x509.v3.CodeV3;

/**
 *
 * @author ra160248d
 */
public class MyCode extends CodeV3 {


    private KeyStore localKeyStore;
    private String CsrFile;
    private static String keyStorePass;
    private static String keyStoreFilePath;

    static {
        Security.addProvider(new BouncyCastleProvider());
        keyStorePass = "ZP19IR3_RA0248/2016";
        keyStoreFilePath = "localKeyStore.p12";

    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {

        super(algorithm_conf, extensions_conf, extensions_rules);

    }

    @Override
    public Enumeration<String> loadLocalKeystore() {

        File ksFile = new File(keyStoreFilePath);
        FileInputStream in = null;
        try {

            if (ksFile.exists()) {
                in = new FileInputStream(ksFile);
            }
            localKeyStore = KeyStore.getInstance("PKCS12", "BC");
            localKeyStore.load(in, keyStorePass.toCharArray());
            return localKeyStore.aliases();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            reportError(ex);
            ex.printStackTrace();
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    reportError(ex);
                    ex.printStackTrace();
                }
            }
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {

        File ksFile = new File(keyStoreFilePath);
        ksFile.delete();
        loadLocalKeystore();

    }

    @Override
    public int loadKeypair(String string) {

        try {
            if (!localKeyStore.containsAlias(string)) {
                return -1; //Should not happen
            }
            X509Certificate toLoad = (X509Certificate) localKeyStore.getCertificate(string);
            JcaX509CertificateHolder certEncaps = new JcaX509CertificateHolder(toLoad);
            X500Name subjectInfo = certEncaps.getSubject();
            X500Name issuerInfo = certEncaps.getIssuer();
            //Subject Info
            this.access.setSubject(subjectInfo.toString());
            //CA Info
            this.access.setIssuer(issuerInfo.toString());
            this.access.setIssuerSignatureAlgorithm(toLoad.getSigAlgName());
            //Cert. Version
            this.access.setVersion(certEncaps.getVersionNumber() - 1);
            //Cert. Serial Number
            this.access.setSerialNumber(certEncaps.getSerialNumber().toString());
            //Time Validity
            this.access.setNotAfter(toLoad.getNotAfter());
            this.access.setNotBefore(toLoad.getNotBefore());
            //Algo
            String algo = toLoad.getPublicKey().getAlgorithm();
            this.access.setPublicKeyAlgorithm(algo);
            this.access.setPublicKeyDigestAlgorithm(toLoad.getSigAlgName());
            this.access.setSubjectSignatureAlgorithm(algo);

            int len = -1;
            switch (algo) {
                case "RSA":
                    len = ((RSAPublicKey) toLoad.getPublicKey()).getModulus().bitLength();
                    this.access.setPublicKeyParameter(len + "");
                    break;
                case "DSA":
                    len = ((DSAPublicKey) toLoad.getPublicKey()).getParams().getP().bitLength();
                    this.access.setPublicKeyParameter(len + "");
                    break;
                case "EC":
                    //????
                    break;

            }

            //Cert. Extensions BasicConstraints,IssuerAlternativeNames,SubjectKeyIdentifier
            Extensions exts = certEncaps.getExtensions();

            if (exts.getExtension(Extension.basicConstraints) != null) {
                BasicConstraints bc = BasicConstraints.fromExtensions(exts);
                this.access.setCritical(gui.Constants.BC, exts.getExtension(Extension.basicConstraints).isCritical());
                this.access.setCA(bc.isCA());
                if (bc.isCA()) {
                    this.access.setPathLen(bc.getPathLenConstraint().toString());
                }
            }

            if (exts.getExtension(Extension.issuerAlternativeName) != null) {
                GeneralNames gns = GeneralNames.fromExtensions(exts, Extension.issuerAlternativeName);
                this.access.setCritical(gui.Constants.IAN, exts.getExtension(Extension.issuerAlternativeName).isCritical());
                StringBuffer sb = new StringBuffer();
                for (GeneralName gn : gns.getNames()) {
                    sb.append(gn.getName()).append(",");
                }
                this.access.setAlternativeName(gui.Constants.IAN, sb.toString());
            }

            if (exts.getExtension(Extension.issuerAlternativeName) != null) {
                SubjectKeyIdentifier skid = SubjectKeyIdentifier.fromExtensions(exts);
                this.access.setCritical(gui.Constants.SKID, exts.getExtension(Extension.subjectKeyIdentifier).isCritical());
                StringBuffer sb = new StringBuffer();
                for (byte b : skid.getKeyIdentifier()) {
                    sb.append(String.format("%02x", b)).append(":");
                }
                this.access.setSubjectKeyID(sb.toString());
            }
            
            if (localKeyStore.isCertificateEntry(string)) return 2;
            else if (localKeyStore.getCertificateChain(string).length > 1) return 1;
            else return 0;

        } catch (KeyStoreException | CertificateEncodingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            reportError(ex);
            return -1;
        }

    }

    @Override
    //RSA Only
    public boolean saveKeypair(String string) {

        if (this.access.getPublicKeyAlgorithm() != "RSA") {
            reportError("Chosen Algorith has not been implemented. Use RSA.");
            return false;
        }
        if (this.access.getSerialNumber() == "") {
            reportError("Serial number has not been generated.");
            return false;
        }
        try {
            if (localKeyStore.containsAlias(string)) {
                reportError("Chosen alias already in use");
                return false;
            }
        } catch (KeyStoreException ex) {
        }
        try {
            //Key Generation
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(Integer.parseInt(this.access.getPublicKeyParameter()));
            KeyPair pair = kpg.genKeyPair();

            //Cert. Generation
            X500Name subject = new X500Name(this.access.getSubject());
            //Self-Signed
            X509v3CertificateBuilder cb = new X509v3CertificateBuilder(
                    subject, new BigInteger(this.access.getSerialNumber()),
                    this.access.getNotBefore(), this.access.getNotAfter(),
                    subject,
                    SubjectPublicKeyInfo.getInstance(new ASN1InputStream(pair.getPublic().getEncoded()).readObject()));

            //Subjcet Key Identifier
            SubjectKeyIdentifier skid = (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(pair.getPublic());
            cb.addExtension(Extension.subjectKeyIdentifier, this.access.isCritical(gui.Constants.SKID), skid);
            //Issuer Alternative Names
            if (this.access.getAlternativeName(gui.Constants.IAN).length != 0) {
                GeneralName[] genNameArr = new GeneralName[this.access.getAlternativeName(gui.Constants.IAN).length];
                for (int i = 0; i < genNameArr.length; i++) {
                    genNameArr[i] = tryToFormatISAN(this.access.getAlternativeName(gui.Constants.IAN)[i]);
                    if (genNameArr[i] == null) {
                        reportError("Error while processing ISAN [" + this.access.getAlternativeName(gui.Constants.IAN)[i] + "]"
                                + "The ISAN include : Email addresses,IP addresses, URIs,DNS names,"
                                + "directory names,other names");
                    }
                }
                GeneralNames issuerAltNames = GeneralNames.getInstance(new DERSequence(genNameArr));
                cb.addExtension(Extension.issuerAlternativeName, this.access.isCritical(gui.Constants.IAN), issuerAltNames);
            }
            //Basic Constraints
            BasicConstraints bc;
            if (this.access.isCA()) {
                bc = new BasicConstraints(Integer.parseInt(this.access.getPathLen()!="" ? this.access.getPathLen() : "0"));
            } else {
                bc = new BasicConstraints(false);
            }
            cb.addExtension(Extension.basicConstraints, this.access.isCritical(gui.Constants.BC), bc);

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.access.getPublicKeyDigestAlgorithm());
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(pair.getPrivate().getEncoded()));

            //Building and converting
            X509Certificate newCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cb.build(sigGen));

            localKeyStore.setKeyEntry(string, pair.getPrivate(), keyStorePass.toCharArray(), new Certificate[]{newCert});
            updateFile();

            return true;

        } catch (NoSuchAlgorithmException | IOException | OperatorCreationException | CertificateException | KeyStoreException ex) {
            reportError(ex);
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

    }

    @Override
    public boolean removeKeypair(String string) {

        try {
            localKeyStore.deleteEntry(string);
            updateFile();
            return true;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

    }

    @Override
    public boolean importKeypair(String keypair_name, String file, String password) {

        try {
            KeyStore ksTmp = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream in = new FileInputStream(file);
            ksTmp.load(in, password.toCharArray());
            if (ksTmp.size() == 0) {
                reportError("Chosen file is empty");
                in.close();
                return false;
            } else {
                if (localKeyStore.containsAlias(keypair_name)) {
                    reportError("Chosen alias already in use.");
                    in.close();
                    return false;
                }
                Enumeration<String> aliases = ksTmp.aliases();
                String toExtract = aliases.nextElement();
                while (!ksTmp.isKeyEntry(toExtract)) {
                    toExtract = aliases.nextElement();
                }
                localKeyStore.setKeyEntry(keypair_name, ksTmp.getKey(toExtract, password.toCharArray()),
                        keyStorePass.toCharArray(), ksTmp.getCertificateChain(toExtract));
                updateFile();
                in.close();
                return true;

            }
        } catch (IOException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException ex) {
            reportError(ex);
        }
        return false;

    }

    @Override
    public boolean exportKeypair(String keypair_name, String file, String password) {
        try {
            KeyStore tmpKs = KeyStore.getInstance("PKCS12", "BC");
            tmpKs.load(null, password.toCharArray());
            tmpKs.setKeyEntry(keypair_name,
                    localKeyStore.getKey(keypair_name, keyStorePass.toCharArray()),
                    password.toCharArray(),
                    localKeyStore.getCertificateChain(keypair_name));

            FileOutputStream out = new FileOutputStream(file);
            tmpKs.store(out, password.toCharArray());
            out.close();
            return true;
        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException
                | UnrecoverableKeyException | CertificateException ex) {
            reportError(ex);
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return false;

        }
    }

    @Override
    public boolean importCertificate(String file, String alias) {

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            FileInputStream in = new FileInputStream(file);
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(in);
            localKeyStore.setCertificateEntry(alias, certificate);
            updateFile();
            return true;
        } catch (CertificateException | NoSuchProviderException | KeyStoreException | IOException | NoSuchAlgorithmException ex) {
            reportError(ex);
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

    }

    @Override
    public boolean exportCertificate(String file, String alias, int encoding, int format) {

        try {
            FileOutputStream out = new FileOutputStream(file,true);
            Certificate[] certs = localKeyStore.getCertificateChain(alias);
            int sz = format == 0 ? 1 : certs.length;
            if(encoding == 0){
                for(int i = 0; i<sz; i++) out.write(certs[i].getEncoded());
            }
            else{
                for(int i = 0; i<sz; i++){
                    
                    BASE64Encoder encoder = new BASE64Encoder();
                    out.write(X509Factory.BEGIN_CERT.getBytes());
                    out.write("\n".getBytes());
                    encoder.encodeBuffer(certs[i].getEncoded(), out);
                    out.write(X509Factory.END_CERT.getBytes());
                    out.write("\n".getBytes());
                    
                }
            }

            out.close();
            return true;
            
            
        } catch (KeyStoreException | CertificateEncodingException | IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
        
    }

    @Override
    public boolean exportCSR(String file, String alias, String algorithm) {

        try {
            //Constructing PKCS10CSR from X509Cert
            X509Certificate cert = (X509Certificate) localKeyStore.getCertificate(alias);
            KeyPair pair = new KeyPair(cert.getPublicKey(), (PrivateKey) localKeyStore.getKey(alias, keyStorePass.toCharArray()));
            Principal princ = cert.getSubjectDN();
            X500Name name = new X500Name(princ.toString());
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    name, pair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm);//REMOVE ME!!!!
            ContentSigner signer = csBuilder.build(pair.getPrivate());

            //Adding Extensions
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            if (holder.getExtension(Extension.basicConstraints) != null) {
                extGen.addExtension(holder.getExtension(Extension.basicConstraints));
            }
            if (holder.getExtension(Extension.subjectKeyIdentifier) != null) {
                extGen.addExtension(holder.getExtension(Extension.subjectKeyIdentifier));
            }
            if (holder.getExtension(Extension.issuerAlternativeName) != null) {
                extGen.addExtension(holder.getExtension(Extension.issuerAlternativeName));
            }
            p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            PKCS10CertificationRequest csr = p10Builder.build(signer);

            OutputStreamWriter output = new OutputStreamWriter(new FileOutputStream(file));
            JcaPEMWriter pem = new JcaPEMWriter(output);
            pem.writeObject(csr);
            pem.close();

            return true;

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException | IOException | CertificateEncodingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

    }

    @Override
    public String importCSR(String file) {

        PEMParser reader = null;
        CsrFile = file;
        try {
            reader = new PEMParser(new FileReader(new File(file)));
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reader.readPemObject().getContent());

            //Attributes - Only one entry encoded, passing possible Cert. params to the GUI
            Extensions exts = Extensions.getInstance(csr.getAttributes()[0].getAttrValues().getObjectAt(0));

            if (exts.getExtension(Extension.basicConstraints) != null) {
                BasicConstraints bc = BasicConstraints.fromExtensions(exts);
                this.access.setCritical(gui.Constants.BC, exts.getExtension(Extension.basicConstraints).isCritical());
                this.access.setCA(bc.isCA());
                if (bc.isCA()) {
                    this.access.setPathLen(bc.getPathLenConstraint().toString());
                }
            }

            if (exts.getExtension(Extension.issuerAlternativeName) != null) {
                GeneralNames gns = GeneralNames.fromExtensions(exts, Extension.issuerAlternativeName);
                this.access.setCritical(gui.Constants.IAN, exts.getExtension(Extension.issuerAlternativeName).isCritical());
                StringBuffer sb = new StringBuffer();
                for (GeneralName gn : gns.getNames()) {
                    sb.append(gn.getName()).append(",");
                }
                this.access.setAlternativeName(gui.Constants.IAN, sb.toString());
            }

            if (exts.getExtension(Extension.issuerAlternativeName) != null) {
                SubjectKeyIdentifier skid = SubjectKeyIdentifier.fromExtensions(exts);
                this.access.setCritical(gui.Constants.SKID, exts.getExtension(Extension.subjectKeyIdentifier).isCritical());
                StringBuffer sb = new StringBuffer();
                for (byte b : skid.getKeyIdentifier()) {
                    sb.append(String.format("%02x", b)).append(":");
                }
                this.access.setSubjectKeyID(sb.toString());
            }
            return csr.getSubject().toString();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                reader.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    @Override
    public boolean signCSR(String file, String issuer_alias, String algorithm) {

        PEMParser reader = null;
        try {
            reader = new PEMParser(new FileReader(new File(CsrFile)));
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reader.readPemObject().getContent());
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr.getEncoded()).setProvider("BC");

            X500Name subject = csr.getSubject();
            X500Name issuer = new X500Name(this.access.getIssuer());
            X509v3CertificateBuilder cb = new X509v3CertificateBuilder(
                    issuer, new BigInteger(this.access.getSerialNumber()),
                    this.access.getNotBefore(), this.access.getNotAfter(),
                    subject,
                    csr.getSubjectPublicKeyInfo());

            //Subjcet Key Identifier
            SubjectKeyIdentifier skid = (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(jcaCsr.getPublicKey());
            cb.addExtension(Extension.subjectKeyIdentifier, this.access.isCritical(gui.Constants.SKID), skid);
            //Issuer Alternative Names
            if (this.access.getAlternativeName(gui.Constants.IAN).length != 0) {
                GeneralName[] genNameArr = new GeneralName[this.access.getAlternativeName(gui.Constants.IAN).length];
                for (int i = 0; i < genNameArr.length; i++) {
                    genNameArr[i] = tryToFormatISAN(this.access.getAlternativeName(gui.Constants.IAN)[i]);
                    if (genNameArr[i] == null) {
                        reportError("Error while processing ISAN [" + this.access.getAlternativeName(gui.Constants.IAN)[i] + "]"
                                + "The ISAN include : Email addresses,IP addresses, URIs,DNS names,"
                                + "directory names,other names");
                    }
                }
                GeneralNames issuerAltNames = GeneralNames.getInstance(new DERSequence(genNameArr));
                cb.addExtension(Extension.issuerAlternativeName, this.access.isCritical(gui.Constants.IAN), issuerAltNames);
            }
            //Basic Constraints
            BasicConstraints bc;
            if (this.access.isCA()) {
                bc = new BasicConstraints(Integer.parseInt(this.access.getPathLen()));
            } else {
                bc = new BasicConstraints(false);
            }
            cb.addExtension(Extension.basicConstraints, this.access.isCritical(gui.Constants.BC), bc);

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(
                    localKeyStore.getKey(issuer_alias, keyStorePass.toCharArray()).getEncoded()));

            //Building chain
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cb.build(sigGen));
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificate(cb.build(sigGen));
            Certificate[] issuerChain = localKeyStore.getCertificateChain(issuer_alias);
            for (Certificate c : issuerChain) {
                generator.addCertificate(new JcaX509CertificateHolder((X509Certificate) c));
            }
            //Writing to file
            CMSSignedData data = generator.generate(new CMSProcessableByteArray("CA Reply".getBytes()), true);
            FileOutputStream out = new FileOutputStream(file);
            out.write(data.getEncoded());
            out.close();
            return true;

        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException | CertificateException | CMSException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                reader.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return false;

    }

    @Override
    public boolean importCAReply(String file, String alias
    ) {

        FileInputStream fis = null;
        try {
            File file_ = new File(file);
            fis = new FileInputStream(file_);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection c = cf.generateCertificates(fis);
            X509Certificate[] chain = (X509Certificate[]) c.toArray();
            
            PrivateKey k = (PrivateKey) localKeyStore.getKey(alias, keyStorePass.toCharArray());
            localKeyStore.deleteEntry(alias);
            localKeyStore.setKeyEntry(alias, k, keyStorePass.toCharArray(), chain);
            updateFile();
            return true;
           
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fis.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return false;
    }

    @Override
    public boolean canSign(String string
    ) {
        try {
            X509Certificate toLoad = (X509Certificate) localKeyStore.getCertificate(string);
            return toLoad.getBasicConstraints() != -1 && !localKeyStore.isCertificateEntry(string);
        } catch (KeyStoreException ex) {
            return false;
        }
    }

    @Override
    public String getSubjectInfo(String string
    ) {
        try {
            X509Certificate toLoad = (X509Certificate) localKeyStore.getCertificate(string);
            JcaX509CertificateHolder certEncaps = new JcaX509CertificateHolder(toLoad);
            return certEncaps.getSubject().toString();
        } catch (KeyStoreException | CertificateEncodingException ex) {
            reportError(ex);
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public static void main(String[] args) {
        
        code.X509.main(args);
        
    }

    private void updateFile() throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        FileOutputStream out = new FileOutputStream(keyStoreFilePath);
        localKeyStore.store(out, keyStorePass.toCharArray());
        out.close();

    }

    //Responsibility delegation
    private GeneralName tryToFormatISAN(String string) {

        try {
            return new GeneralName(GeneralName.dNSName, string);
        } catch (Exception ex1) {
            try {
                return new GeneralName(GeneralName.directoryName, string);
            } catch (Exception ex2) {
                try {
                    return new GeneralName(GeneralName.ediPartyName, string);
                } catch (Exception ex3) {
                    try {
                        return new GeneralName(GeneralName.iPAddress, string);
                    } catch (Exception ex4) {
                        try {
                            return new GeneralName(GeneralName.otherName, string);
                        } catch (Exception ex5) {
                            try {
                                return new GeneralName(GeneralName.registeredID, string);
                            } catch (Exception ex6) {
                                try {
                                    return new GeneralName(GeneralName.rfc822Name, string);
                                } catch (Exception ex7) {
                                    try {
                                        return new GeneralName(GeneralName.uniformResourceIdentifier, string);
                                    } catch (Exception ex8) {
                                        try {
                                            return new GeneralName(GeneralName.x400Address, string);
                                        } catch (Exception ex9) {
                                            return null;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public String getCertPublicKeyAlgorithm(String string) {
        
        try {
            X509Certificate toLoad = (X509Certificate) localKeyStore.getCertificate(string);
            return toLoad.getPublicKey().getAlgorithm();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    }

    @Override
    public String getCertPublicKeyParameter(String string) {
         
        try {
            X509Certificate toLoad = (X509Certificate) localKeyStore.getCertificate(string);
            switch (toLoad.getPublicKey().getAlgorithm()) {
                case "RSA":
                    return ((RSAPublicKey) toLoad.getPublicKey()).getModulus().bitLength()+"";
                case "DSA":
                    return ((DSAPublicKey) toLoad.getPublicKey()).getParams().getP().bitLength()+"";
                case "EC":
                    //????
                    return "";

            }
     
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
     
               return "";
    }

   

}
