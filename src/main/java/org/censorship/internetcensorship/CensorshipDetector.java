package org.censorship.internetcensorship;

import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import org.xbill.DNS.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@ShellComponent
public class CensorshipDetector {

    @ShellMethod("Detect censorship")
    public String detectCensorship (
            @ShellOption String webAddress
    ) throws Exception, UndeclaredThrowableException {
        String genuineAddress = webAddress;
        if(!webAddress.contains("http"))
            webAddress = "http://".concat(webAddress);
       /* String s;

        System.out.println("-----------------ooni probe is starting-----------------");
        Process ooniProbe = Runtime.getRuntime().exec("ooniprobe web_connectivity --url "+webAddress);
        BufferedReader reader = new BufferedReader(new InputStreamReader(ooniProbe.getInputStream()));
        while((s=reader.readLine())!=null)
            System.out.println(s);
        System.out.println("-----------------ooni probe finished--------------------");


        System.out.println("-----------------Manual Check Starting-----------------");


        System.out.println("Checking whether open-dns are supported or not");
        Process nmapProbe = Runtime.getRuntime().exec("nmap -sU -p 53 --script=dns-recursion 8.8.8.8");
        reader = new BufferedReader(new InputStreamReader(nmapProbe.getInputStream()));

        while((s=reader.readLine())!=null){
            System.out.println(s);
            if(s.contains("dns-recursion: Recursion appears to be enabled"))
                System.out.println("Recursion is enabled, so Open-Dns is supported");
        }

        System.out.println("Checking dns based censorship");




        try{
            URL url = new URL(webAddress);
            URLConnection urlConnection = url.openConnection();
            urlConnection.connect();

        }catch (MalformedURLException e){
            System.out.println("Url is not in correct format");
        }catch (IOException e){
            System.out.println("Connection failed, can't open connection");
        }
*/


       checkDnsCensorship(genuineAddress);
        return "Command completed";
    }


    private void checkDnsCensorship(String webAddress) throws Exception{
        System.out.println("Testing with ISP Dns Server");
        String ipAddress = InetAddress.getByName(webAddress).getHostAddress();
        System.out.println("Found Ip Address-->"+ipAddress);
        System.out.println("Testing with opendns");
        SimpleResolver resolver = new SimpleResolver("8.8.8.8");
        Lookup lookup = new Lookup(webAddress);
        lookup.setResolver(resolver);
        Record[] results =  lookup.run();
        List<Record> records = new ArrayList<>();
        List<String> ipAddressOfRecords = new ArrayList<>();
        if(results==null)
            System.out.println("Not able to connect");
        else{
            records = Arrays.asList(results);
            Collections.shuffle(records);
            for(Record record: records){
                System.out.println(((ARecord) record).getAddress().getHostAddress());
                ipAddressOfRecords.add(((ARecord) record).getAddress().getHostAddress());
            }
        }

        if(ipAddressOfRecords.contains(ipAddress))
            System.out.println("No DNS tempering detected");
        else
            System.out.println("DNS tempering detected");

//        System.out.println(lookup.getAnswers());
//
//        InetAddress address = Address.getByAddress(genuineAddress);
    }
}
