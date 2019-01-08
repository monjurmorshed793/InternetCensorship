package org.censorship.internetcensorship;

import com.google.common.collect.MapDifference;
import com.google.common.collect.Maps;
import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.TorInitializationListener;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.springframework.stereotype.Service;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

@Service
public class CensorshipDetectorService {
    public void testOONIProbe(String webAddress) throws IOException {
        String s;

        System.out.println("-----------------ooni probe is starting-----------------");
        Process ooniProbe = Runtime.getRuntime().exec("ooniprobe web_connectivity --url "+webAddress);
        BufferedReader reader = new BufferedReader(new InputStreamReader(ooniProbe.getInputStream()));
        while((s=reader.readLine())!=null)
            System.out.println(s);
        System.out.println("-----------------ooni probe finished--------------------");
    }


    public boolean  checkDnsCensorship(String webAddress) throws Exception{
        boolean isDnsCensorshipDetected = false;
        System.out.println("Testing with ISP Dns Server");
        String ipAddress = "";
        try{
            ipAddress = InetAddress.getByName(webAddress).getHostAddress();
            System.out.println("Found Ip Address-->"+ipAddress);
        }catch (Exception e){
            System.out.println("ISP DNS NO RESPONSE");
            e.printStackTrace();
        }

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

        if(ipAddressOfRecords.contains(ipAddress)){
            System.out.println("No DNS tempering detected");
        }
        else{
            isDnsCensorshipDetected = true;
            System.out.println("DNS tempering detected");
        }

//        System.out.println(lookup.getAnswers());
//
//        InetAddress address = Address.getByAddress(genuineAddress);
        return isDnsCensorshipDetected;
    }

    public boolean checkHttpCensorship(String webAddress)throws Exception{


        System.out.println("Checking HTTP Censorship");

        boolean isHttpCensorshipDetected = false;

        Map<String, String> proxyHeaderElements  = getProxyHeaderElements(webAddress);

        if(proxyHeaderElements==null){
            System.out.println("Website or link is not accessible through proxy, it may be down or the address is changed");
            return false;
        }

        Map<String, String> ispHeaderElements =getISPHeaderElements(webAddress);

        if(ispHeaderElements==null){
            System.out.println("TCP/IP Censorship Detected");
            return false;
        }
        else if(ispHeaderElements.size()==0)
            return isHttpCensorshipDetected ;


        MapDifference<String, String> differenceInMaps = Maps.difference(ispHeaderElements, proxyHeaderElements);

        //need to validate more
        if(differenceInMaps.entriesInCommon().size()<1)
            isHttpCensorshipDetected = true;
        System.out.println("HTTP Censorship detection finished");
        if(isHttpCensorshipDetected)
            System.out.println("HTTP Censorship detected");
        else
            System.out.println("No HTTP Censorship detected");
        return isHttpCensorshipDetected;
    }


    /*
    * HTTP port---> 80
    * HTTPS port ---> 443
    *
    * */
    private Map<String, String> getProxyHeaderElements(String webAddress) throws Exception{
        webAddress = webAddress.replace("http://","");
        HttpHost proxy = new HttpHost("200.89.125.178", 45274, "http");
        DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);

        CloseableHttpClient httpClient = HttpClients.custom()
                .setRoutePlanner(routePlanner)
                .build();

        HttpHost target = new HttpHost(webAddress, 80, "http");
        HttpGet req = new HttpGet("/");
        Map<String, String>  headers = new HashMap<>();
        try{
            CloseableHttpResponse response  = httpClient.execute(target, req);
            for(Header header: response.getAllHeaders()){
                headers.put(header.getName(), header.getValue());
            }
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }

        return headers;

    }

    private HttpResponse getHttpResponse(String webAddress, org.apache.http.client.HttpClient httpClient) throws IOException {
        webAddress = webAddress.replace("http://", "");
        HttpHost target = new HttpHost(webAddress, 80,"http");
        HttpGet req = new HttpGet("/");
        try{
            return httpClient.execute(target, req);
        }catch (HttpHostConnectException e){

            return null;
        }
    }


    private Map<String, String> getISPHeaderElements(String webAddress) throws Exception{
        org.apache.http.client.HttpClient httpClient = HttpClientBuilder.create().build();
        HttpResponse response = getHttpResponse(webAddress, httpClient);
        if(response==null)
            return null;
        ((CloseableHttpClient) httpClient).close();

        Map<String, String>  headers = new HashMap<>();
        for(Header header: response.getAllHeaders()){
            headers.put(header.getName(), header.getValue());
        }
        return headers;
    }



    public boolean checkConnectionStatus( String webAddress) {
        System.out.println("Checking website or link rechability");
        boolean isConnectable = false;
        try{
            URL url = new URL(webAddress);
            URLConnection urlConnection = url.openConnection();
            urlConnection.connect();
            isConnectable = true;

        }catch (MalformedURLException e){
            System.out.println("Url is not in correct format");
        }catch (IOException e){
            System.out.println("Connection failed, can't open connection");
        }

        return isConnectable;
    }



}
