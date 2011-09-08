import jpcap.*;
import jpcap.packet.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
    
class Sniffer implements PacketReceiver {
    static int chikka = 0;
    static int meebo = 0;
    static int fb = 0;
    static JpcapCaptor jpcap;  
    static int Dilnet = 1; //1 if in Dilnet with proxy, else 0    
    static FileWriter fw;
    static String from="";
    static String to="";
    static String fromM="";
    static String toM="";    
    static String message="";
    static String session="";
    
    public void receivePacket(Packet packet) {           
        
        String data = new String(packet.data);
        String pack = new String(packet.toString());
        String B; String A;
        int previousStat=0;
        int start = 0;
        int end = 0;
                    
        //START CHIKKA
   		if((chikka==1)&&
   		(data.indexOf("=\"jabber:client\" to=\"")!=-1)&& 
   		(data.indexOf("type=\"chat\"")!=-1)){
   		// main part of chikka packet
   		    System.out.println("-----------------------SENT-----------------------");
       		System.out.println("Time: " + this.getDateTime(1));
            while(data.indexOf("<body>")!=-1){
                start = pack.indexOf("/");            
                end = pack.indexOf("->/");
                String ip = pack.substring(start +1, end);
                System.out.println("src ip: "+ip);
                
                start = data.indexOf("\" to=\"") + 6;
                end = data.indexOf(" type=\"chat\"><body>");
                to = data.substring(start, end-1);
           	    System.out.println("receiver: " + to);

                start = data.indexOf("</body>");
                message = data.substring(end + 19, start);
           	    System.out.println("message: " + message + "\n");
           	    
           	    end = data.indexOf("</message>");
           	    data = data.substring(end+10, data.length());
           	    
           	    //session logging
                try {
			        fw = new FileWriter("chikka/" + to + ".txt", true);
                    fw.append(this.getDateTime(1));
			        fw.append(" " + from + ": ");
			        fw.append(message + "\n");
		        } 
			    catch (IOException e) {} 
			    try {
	                fw.close();
                } catch (IOException e) {}
                //dumpfile logging
			    try {
			        fw = new FileWriter("chikka/" + this.getDateTime(0) + "-logfile.txt", true);
			        fw.append("\n" + this.getDateTime(1) + " to: "+ to + " from: " + ip + ": " + message);
		        } 
			    catch (IOException e) {}  
                try {
	                fw.close();
                } catch (IOException e) {} 
            }
            
   		}
   		if((chikka==1)&&
   		    (data.indexOf(" type='chat'")!=-1&&
       		data.indexOf("xmlns='http://jabber.org/protocol/httpbind'")!=-1)){
       		//Chika recieve packet
   		    System.out.println("-----------------------RECEIVED-----------------------");
       		System.out.println("Time: " + this.getDateTime(1));
       	    while(data.indexOf("<body")!=-1){
       	        System.out.println("into while");
           	    start = data.indexOf("' to='") + 7;
                end = data.indexOf("type='chat'") -1;
                to = data.substring(start, end);
           	    System.out.println("receiver: " + to);

                start = data.indexOf("client' from='");
                end = data.indexOf(".im/aurora'");
                from = data.substring(start + 14, end-13);
           	    System.out.println("sender: " + from);
           	    
                start = data.indexOf("type='chat'><body>");
                end = data.indexOf("</body>");
                message = data.substring(start+18,end);
           	    System.out.println("message: " + message + "\n");
           	    
           	    end = data.indexOf("</message>");
           	    data = data.substring(end+10, data.length());
           	    
           	    //session logging
           	    try {
			        fw = new FileWriter("chikka/" + from + ".txt", true);
                    fw.append(this.getDateTime(1));
			        fw.append("to: "+to + " ");
			        fw.append("from: "+ from + ": ");
			        fw.append(message + "\n");
		        } 
			    catch (IOException e) {}
                try {
	                fw.close();
                } catch (IOException e) {}  
                //dump logging
			    try {
			        fw = new FileWriter("chikka/" + this.getDateTime(0) + "-logfile.txt", true);
			        fw.append("\n" + this.getDateTime(1) + " to: "+ to + " from: " + from + ": " + message);
		        } 
			    catch (IOException e) {}  
                try {
	                fw.close();
                } catch (IOException e) {}  
       	    }
   		}
       	//END CHIKKA
       	
       	//START MEEBO
       	if(meebo==1){
            if((data.indexOf("&sender=")!=-1)&&(data.indexOf("mcmd")!=-1)&&(data.indexOf("POST")!=-1)){
            //Meebo first and main part of send packet
        	        System.out.println("-----------------------SENT------------------------");
               		System.out.println("SENT!!!"); 
               	    
               	    start = data.indexOf("&sender=") + 8;
                    end = data.indexOf("&receiver=");
                    fromM = data.substring(start, end);

                    start = data.indexOf("&protocol=");
                    toM= data.substring(end+10, start);
                    
                    start = data.indexOf("&msg=");
                    message= data.substring(start + 5, data.length());
                    System.out.println("Time: " + this.getDateTime(1));
                    System.out.println("receiver: "+toM + "\nsender: "+ fromM + "\nmessage: " + message);
                    // logging per session                    
                    try {
			            fw = new FileWriter("meebo/" +  this.getDateTime(0)+ fromM +"-"+toM + ".txt", true);
                        fw.append("\n"+this.getDateTime(1));
			            fw.append(" " + fromM + ": ");
			            fw.append(message);
		            } 
    			    catch (IOException e) {} 
                    try {
    	                fw.close();
                    } catch (IOException e) {}
                    // dumpfile of all messages
                    try {
	                    fw = new FileWriter("meebo/" + this.getDateTime(0) + "-logfile.txt", true);
	                    fw.append("\n" + this.getDateTime(1) + " to: "+ toM + "from: " + fromM + ": " + message);
                    } 
	                catch (IOException e) {} 
                    try {
                        fw.close();
                    } catch (IOException e) {}
                if(data.indexOf("clientId")==-1){
                    previousStat=1; // message was cut short
                }
            }
                
   	        else if((previousStat==1)&&(data.indexOf("clientId=")!=-1)&& (data.indexOf("GET")==-1)){
   	            //second part of meebo send packet
           	    previousStat=0;
           	    try {
		        fw = new FileWriter("meebo/" + this.getDateTime(0)+fromM +"-"+toM + ".txt", true);
		        fw.append(data);
	            } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {}
           	    System.out.println(data);
                // dumpfile of all messages
                try {
			        fw = new FileWriter("facebook/" + this.getDateTime(0) + "-logfile.txt", true);
			        fw.append(message);
		        } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {}               	   
            }
       	    
       	    else if(data.indexOf("im::received")!=-1){
       	        // meebo receive packet
       	        System.out.println("-----------------------RECIEVED----------------------");
       	        System.out.println("Time: " + this.getDateTime(1));
           		
           		start = data.indexOf("sender\":") + 9;
                end = data.indexOf("\",\"receiver\":\"");
                from = data.substring(start, end);
           	    System.out.println("sender: " + from);
           	    
                start = data.indexOf("\",\"protocol\":\"");
                to = data.substring(end + 14,start);
           	    System.out.println("receiver: " + to);

                start = data.indexOf("\",\"message\":\"") +13;
                end = data.indexOf("\",\"timeSentUTC");
                message = data.substring(start,end);
           	    System.out.println("sender: " + message);
                //session logging           	    
           	    try {
			        fw = new FileWriter("meebo/" + this.getDateTime(0)+to + "-" +from+ ".txt", true);
                    fw.append("\n"+this.getDateTime(1));
			        fw.append(" " + from + ": ");
			        fw.append(message + "\n\n");
		        } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {}
                // dumpfile of all messages
                try {
			        fw = new FileWriter("meebo/" + this.getDateTime(0) + "-logfile.txt", true);
			        fw.append("\n" + this.getDateTime(1) + " to: "+ to + "from: " + from + ": " + message);
		        } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {}
   	            System.out.println("-----------------------END--------------------------"); 
       	    }
       	}
       	//END MEEBO
       	
       	//START FB
       	if(fb==1){
       	    if((data.indexOf("{\"msg\":{")!=-1)&&(data.indexOf("\"msgID\"")!=-1)&&(data.indexOf("\"from_name\"")!=-1)){
                // fb send and receive packet                
           		System.out.println("-----------------------START------------------------");

           	    // from name
           	    start = data.indexOf("\"from_name\"") + 13;
           	    end = data.indexOf(",\"from_first_name\"") - 1;
           	    from = data.substring(start, end);
                // from id
           	    start = data.indexOf("\"from\":") + 7;
           	    end = data.indexOf(",\"to\":");
           	    String from_id = data.substring(start, end);

           	    //to name
           	    start = data.indexOf("to_name") + 10;
           	    end = data.indexOf("\",\"to_first_name");
           	    to = data.substring(start, end);
           	    
           	    //to id
           	    start = data.indexOf(",\"to\":") + 6;
           	    end =  data.indexOf("\"from_name\"")-1;
           	    String to_id = data.substring(start, end);

                //"session"
                start = data.indexOf("(;;);{\"t\":\"msg\",\"c\":\"p_") + 23;
           	    end =  data.indexOf("\",\"s\":");
           	    session = data.substring(start, end);
                
           	    //message
           	    start = data.indexOf("{\"msg\":{\"text\":\"") +16;
           	    end = data.indexOf("\",\"time\"");
           	    message = data.substring(start, end);
           	    
           	    //ip
           	    end = pack.indexOf("->/") +18;
           	    start = end-33;
           	    String ip = pack.substring(start, end);
           	    
           	    
           	    System.out.println("Time: " + this.getDateTime(1));
           	    System.out.println("IP: " + ip);
           	    System.out.println("From: "+ from);
           	    System.out.println("To: "+to);
           	    System.out.println("Message: "+ message); 

           	    // logging by session
           	    if (session.equals(from_id)){ A = from; B = to; }
           	    else{ A = to; B = from; }
       	        try {
			        fw = new FileWriter("facebook/" + this.getDateTime(0) +"-"+ A + "-" + B + ".txt", true);
                    fw.append(this.getDateTime(1));
			        fw.append(" " + from + ": ");
			        fw.append(message + "\n");
		        } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {}  
                System.out.println("-----------------------END--------------------------");

                // dumpfile of all messages
                try {
			        fw = new FileWriter("facebook/" + this.getDateTime(0) + "-logfile.txt", true);
			        fw.append("\n" + this.getDateTime(1) + " to: "+ to + "from: " + from + ": " + message);
		        } 
			    catch (IOException e) {} 
                try {
	                fw.close();
                } catch (IOException e) {} 
       	    }
       	} //end facebook
       	
        
    }

    private String getDateTime(int mode) {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        if(mode==1){
            dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        }
        Date date = new Date();
        return dateFormat.format(date);
    }
    
    public static void main(String[] args) throws Exception {
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		if (args.length<2) {
			System.out.println("usage: sudo java Sniffer <select a number of desired device> <chikka meebo fb>");
			System.out.println("example: sudo java Sniffer 0 meebo chikka fb");
	        System.out.println("example: sudo java Sniffer 0 fb chikka");
			for (int i = 0; i < devices.length; i++) {
				System.out.println(i + " :" + devices[i].name + "(" + devices[i].description + ")");
				System.out.println("    data link:" + devices[i].datalink_name + "(" + devices[i].datalink_description + ")");
				System.out.print("    MAC address:");
				for (byte b : devices[i].mac_address) {
					System.out.print(Integer.toHexString(b&0xff) + ":");
				}
				System.out.println();
				for (NetworkInterfaceAddress a : devices[i].addresses) {
					System.out.println("    address:"+a.address + " " + a.subnet + " " + a.broadcast);
				}
			}
		}
		else {
			jpcap = JpcapCaptor.openDevice(devices[Integer.parseInt(args[0])], 2000, false, 20);
            String [] input = new String[4];
            input[0]=args[1];
            if (args.length>2){
                input[1]=args[2];
                if (args.length == 4){
                    input[2]=args[3];
                }
            }
            for(int i=0; input[i]!=null;i++){           
		        if (input[i].equals("chikka")) {
		            chikka=1;
		            File c = new File("chikka");
			        c.mkdir();
		            if(Dilnet==0){
            		    jpcap.setFilter("host chikka.com", true);
		            }
		        }
		        else if (input[i].equals("meebo")) {
		            meebo = 1;
			        File m = new File("meebo");
			        m.mkdir();
			        if(Dilnet==0){
				        jpcap.setFilter("host meebo.com", true);
			        }
		        }
		        else if(input[i].equals("fb")){
		            fb = 1;
		            File f = new File("facebook");
			        f.mkdir();
		        }
		        else{
			        System.out.println("Choose: chikka, meebo or fb");
			        System.out.println("example: sudo java Sniffer 0 meebo chikka fb");
			        System.out.println("example: sudo java Sniffer 0 fb chikka");
			        System.exit(1);
		        }
            }
            jpcap.loopPacket(-1, new Sniffer());			
		}
	}
}
