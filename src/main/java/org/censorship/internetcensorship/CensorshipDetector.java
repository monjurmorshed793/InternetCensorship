package org.censorship.internetcensorship;

import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@ShellComponent
public class CensorshipDetector {

    @ShellMethod("Detect censorship")
    public String detectCensorship (
            @ShellOption String webAddress
    ) throws Exception{
        if(!webAddress.contains("http"))
            webAddress = "http://".concat(webAddress);
        String s;

        System.out.println("-----------------ooni probe is starting-----------------");
        Process ooniProbe = Runtime.getRuntime().exec("ooniprobe web_connectivity --url "+webAddress);
        BufferedReader reader = new BufferedReader(new InputStreamReader(ooniProbe.getInputStream()));
        while((s=reader.readLine())!=null)
            System.out.println(s);
        System.out.println("-----------------ooni probe finished--------------------");


        System.out.println("-----------------Manual Check Starting-----------------");
        Process nmapProbe = Runtime.getRuntime().exec("nmap -sU -p 53 --script=dns-recursion "+webAddress);
        reader = new BufferedReader(new InputStreamReader(nmapProbe.getInputStream()));

        while((s=reader.readLine())!=null){
            System.out.println(s);
            if(s.contains("dns-recursion: Recursion appears to be enabled"))
                System.out.println("Recursion is enabled");
        }
        return "Command completed";
    }
}
