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

    private CensorshipDetectorService censorshipDetectorService;

    public CensorshipDetector(CensorshipDetectorService censorshipDetectorService) {
        this.censorshipDetectorService = censorshipDetectorService;
    }

    @ShellMethod("Detect censorship")
    public String detectCensorship (
            @ShellOption String webAddress
    ) throws Exception, UndeclaredThrowableException {
        String genuineAddress = webAddress;
        if(!webAddress.contains("http"))
            webAddress = "http://".concat(webAddress);
       // censorshipDetectorService.testOONIProbe(webAddress);


        System.out.println("Censorship test starting");


//        System.out.println("Checking whether open-dns are supported or not");
//        Process nmapProbe = Runtime.getRuntime().exec("nmap -sU -p 53 --script=dns-recursion 8.8.8.8");
//        reader = new BufferedReader(new InputStreamReader(nmapProbe.getInputStream()));
//
//        while((s=reader.readLine())!=null){
//            System.out.println(s);
//            if(s.contains("dns-recursion: Recursion appears to be enabled"))
//                System.out.println("Recursion is enabled, so Open-Dns is supported");
//        }

        boolean canConnect = censorshipDetectorService.checkConnectionStatus(webAddress);

        /*if(canConnect)
            return "No Censorship Is Detected. Command execution finished";*/

        boolean isDnsCensorshipDetected =  censorshipDetectorService.checkDnsCensorship(genuineAddress);

        boolean isHttpCensorshipDetected = censorshipDetectorService.checkHttpCensorship(webAddress);
        return "Command completed";
    }




}
