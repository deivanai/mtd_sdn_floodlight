package net.floodlightcontroller.mtd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Random;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwDst.Builder;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.internal.OFSwitchManager;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packetstreamer.thrift.Packet;


public class mtd1 implements IFloodlightModule, IOFMessageListener, Runnable {
	
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	static Map<String,String> R2V_map = new HashMap<String,String>();// real to virtual IP address map
    static Map<String,String> V2R_map = new HashMap<String,String>();// virtual to real IP address map 
	Map<String,String> host_map = new HashMap<String,String>();// real ip address to switch ip map
	Table<String,String,OFPort>host_switch_port_map = HashBasedTable.create();
	ArrayList<String> datapath = new ArrayList<String> (); // list of switch ids 
	static String[] virtualArrayList = {"10.0.0.9","10.0.0.10","10.0.0.11","10.0.0.12",
	           "10.0.0.13","10.0.0.14","10.0.0.15","10.0.0.16",
	           "10.0.0.17","10.0.0.18","10.0.0.19","10.0.0.20",
	           "10.0.0.21","10.0.0.22","10.0.0.23","10.0.0.24",
	           "10.0.0.25","10.0.0.26","10.0.0.27","10.0.0.28",
	           "10.0.0.29","10.0.0.30","10.0.0.31","10.0.0.32",
	           "10.0.0.33","10.0.0.34","10.0.0.35","10.0.0.36"};
	static OFSwitchManager switchDetails = new OFSwitchManager();
	@Override
	public String getName() {
		return "MTD";
	}
	
	public mtd1() {
		String timerEventGen="TimerEventGen";
		Thread timerEventGenThread = new Thread(this, timerEventGen);
		System.out.println("Thread Started for: " + timerEventGen);
		timerEventGenThread.start();
	} 

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPacketIn packetIn = (OFPacketIn) msg;
        OFPort inPort = packetIn.getMatch().get(MatchField.IN_PORT);
        OFPort outPort = OFPort.FLOOD; 
        
        DatapathId switchId = sw.getId();
        String switchid_str = switchId.toString();
        OFActions ofActions = sw.getOFFactory().actions();
		ArrayList<OFAction> actionList = new ArrayList<OFAction> ();               	
		OFOxms oxms = sw.getOFFactory().oxms();
		ArrayList<OFInstruction>  instructionList = new ArrayList<OFInstruction>(); 
		OFInstructions instructions = sw.getOFFactory().instructions();		    
		
		IPv4Address dest_ip = null , source_ip = null;
		String destip_str = null, sourceip_str = null;
		EthType eth_type = null;
		
		if(eth.getEtherType() == EthType.ARP) {
			eth_type = EthType.ARP;
			ARP arp = (ARP) eth.getPayload();
			dest_ip = arp.getTargetProtocolAddress();
			source_ip = arp.getSenderProtocolAddress();		
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
			MacAddress source_mac = eth.getSourceMACAddress();
			MacAddress dest_mac = eth.getDestinationMACAddress();
					    
			logger.info("packet In message for ARP  dst: " + destip_str + " , source : " + source_ip.toString());
			
			if (V2R_map.containsKey(destip_str) ) {
				String rdestip_str = V2R_map.get(destip_str);
				if(host_switch_port_map.contains(rdestip_str, switchid_str))
		        {
		        	// out port to specific port if dest ip's corresponding port is already known.
		        	logger.info("for dest ip: " + rdestip_str + " port already known");
					outPort = host_switch_port_map.get(rdestip_str,switchid_str);
		        }

				if(isDirectContact(switchid_str,rdestip_str)){
					logger.info("convert to real dest ip if host is attached to current switch " );
					logger.info(destip_str + " => " + rdestip_str + " attached to: " + switchid_str);
					// # add a packet out send with real destination address swapped 
					IPv4Address rdestip = IPv4Address.of(rdestip_str);			  
					arp.setTargetProtocolAddress(rdestip);	
				}
				else
				{
					//if its not direct contact don't change the virtual ip address, just send the packet out to controller. 
				}
			}
			if(R2V_map.containsKey(destip_str)){
				// fix add packet drop case in case some one is trying to ping with real ip dest address 
			}
			if(R2V_map.containsKey(sourceip_str)){
				//learn the in port for any source ip for future use and avoid flooding. 
		        host_switch_port_map.put(sourceip_str, switchid_str, inPort);	        
		        if(!host_map.containsKey(sourceip_str)){
		        	logger.info("learn host map  IP attached to switch: " + sourceip_str  +  "attached to: " + switchid_str );				
					host_map.put(sourceip_str, switchid_str);
		        }
		        
				String vsourceip_str = R2V_map.get(sourceip_str);   
				logger.info(sourceip_str + " changed to => " + vsourceip_str);
				//add a packet out send with real dest address swapped 
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
				arp.setSenderProtocolAddress(vsourceip);				
			}			     
			eth.setPayload(arp);
			
			Match match = sw.getOFFactory().buildMatch()
		    		.setExact(MatchField.IN_PORT, inPort)
		    		.setExact(MatchField.ETH_TYPE, eth_type )
		    		.setExact(MatchField.ETH_SRC, source_mac)
		    		.setExact(MatchField.ETH_DST,dest_mac)
		    		.build();
				
		    
			OFActionOutput output = ofActions.buildOutput()
	       			.setMaxLen(0xFFffFFff)
	       			.setPort(outPort)
	       			.build();
			
		    actionList.add(output);
			if(outPort != OFPort.FLOOD){
				OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
			    		.setBufferId(OFBufferId.NO_BUFFER) // TODO handle fix BufferId later
			    		.setHardTimeout(3600)
			    		.setIdleTimeout(10)
			    		.setPriority(200)
			    		.setTableId(TableId.of(0))
			    		.setMatch(match)
			    		.setActions(actionList)
			    		.build();
				logger.info("flow add: " + flowAdd.toString());
				sw.write(flowAdd);
			}

     	}
		
		if(eth.getEtherType() == EthType.IPv4) {
			eth_type = EthType.IPv4;
			IPv4   ipv4 = (IPv4) eth.getPayload();
			dest_ip = ipv4.getDestinationAddress();
			source_ip = ipv4.getSourceAddress();
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
	        MacAddress source_mac = eth.getSourceMACAddress();
	        MacAddress dest_mac = eth.getDestinationMACAddress();
	        logger.info("packet In message for ICMP for destination: " + destip_str + " source ip: "+ sourceip_str);
				
			if (V2R_map.containsKey(destip_str)){
				logger.info(destip_str + " => "  + V2R_map.get(destip_str) );
				String rdestip_str = V2R_map.get(destip_str);  
				if(host_switch_port_map.contains(rdestip_str, switchid_str))
		        {
		        	// out port to specific port if dest ip's corresponding port is already known.
					logger.info("for dest ip: " + rdestip_str + " port already known");
					outPort = host_switch_port_map.get(rdestip_str,switchid_str);
		        }

				IPv4Address rdestip = IPv4Address.of(rdestip_str);
				//TODO fix change can happen only if its direct contact
				OFActionSetField setDstIp = ofActions.buildSetField()
						.setField(oxms.buildIpv4Dst().setValue(rdestip).build())
						.build();
				actionList.add(setDstIp);
				ipv4.setDestinationAddress(rdestip);
			
			}
			if(R2V_map.containsKey(sourceip_str)){
				logger.info(sourceip_str + " => " + R2V_map.get(sourceip_str));
				//learn the in port for any source ipaddress for future use and avoid flooding. 
		        host_switch_port_map.put(sourceip_str, switchid_str, inPort);
		        if(!host_map.containsKey(sourceip_str)){
					logger.info("learn host map  IP attached to switch: " + source_ip.toString()  +  "attached to: " + switchid_str );				
					host_map.put(sourceip_str, switchid_str);
				}
				String vsourceip_str = R2V_map.get(sourceip_str);   
				//add a packet out send with real dest address swapped 
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
			    ipv4.setSourceAddress(vsourceip);
				OFActionSetField setSourceIp = ofActions.buildSetField()
						.setField(oxms.buildIpv4Src().setValue(vsourceip).build())
						.build();
				actionList.add(setSourceIp);					
			}			      
			eth.setPayload(ipv4);

			Match match = sw.getOFFactory().buildMatch()
			    		.setExact(MatchField.IN_PORT, inPort)
			    		.setExact(MatchField.ETH_TYPE, eth_type )
			    		.setExact(MatchField.IPV4_DST, dest_ip)
			    		.setExact(MatchField.IPV4_SRC, source_ip)
			    		.setExact(MatchField.ETH_SRC, source_mac)
			    		.setExact(MatchField.ETH_DST,dest_mac)
			    		.build();	

		    OFActionOutput output = ofActions.buildOutput()
	       			.setMaxLen(0xFFffFFff)
	       			.setPort(outPort)
	       			.build();
		    actionList.add(output);
		    
		    OFInstructionApplyActions instructionsApplyAction = instructions
		    		.buildApplyActions()
		    		.setActions(actionList)
		    		.build();
		   	instructionList.add(instructionsApplyAction);
		    
		   	if(outPort!= OFPort.FLOOD){
		   		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
		    		.setBufferId(OFBufferId.NO_BUFFER) // TODO handle fix BufferId later
		    		.setHardTimeout(3600)
		    		.setIdleTimeout(10)
		    		.setPriority(200)
		    		.setTableId(TableId.of(0))
		    		.setMatch(match)
		    		.setInstructions(instructionList)
		    		.build();
		    
		   		logger.info("flow add: " + flowAdd.toString());
		   		sw.write(flowAdd);
		   	}

		}
	
	     OFPacketOut packetOut = sw.getOFFactory().buildPacketOut()
       			.setData(eth.serialize())
       			.setActions(actionList)
       			.setInPort(inPort)
       			.build();
	     
	    logger.info("packet out: " + packetOut.toString());
	    sw.write(packetOut);
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService >>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(mtd1.class);

		
		//TODO  fix and initialize empty maps and add a dynamic algorithm to assign virtual to real IP maps with a timer.
		//For now stub the dynamic maps and create a static list to demonstrate routing with virtual address
		   R2V_map.put("10.0.0.1","10.0.0.21");
		   R2V_map.put("10.0.0.2","10.0.0.22");
		   V2R_map.put("10.0.0.21","10.0.0.1");
		   V2R_map.put("10.0.0.22","10.0.0.2");		            
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.FEATURES_REQUEST,this);

	}
	public boolean isRealIPAddress(String ipAddress){
		if(R2V_map.containsKey(ipAddress) )
			return true;
		else
			return false;		
	}
	
	public boolean isVirtualIPAddress(String ipAddress){
		if(V2R_map.containsKey(ipAddress) )
			return true;
		else
			return false;		
	}
	
	public boolean isDirectContact(String dataPath, String ipAddress){
		if(host_map.containsKey(ipAddress)) {
		    if(host_map.get(ipAddress).equals(dataPath))
		    	return true;
		    else
		    	return false;
		}
		return true; // return true if host is not found in host map to proceed further.  
	}
	
	public static void listenToMe(){
		System.out.println("listennig");
	}
	
	public static void updateResources(){
		//update the mapping of real and virtual ip addresses
		//clear flow rules
		//add default entry to switches
		Random rand = new Random();
		int randNum = rand.nextInt(virtualArrayList.length);
		System.out.println("Random number generated is :"+randNum);
		for (String key : R2V_map.keySet()){
			R2V_map.put(key, virtualArrayList[randNum]);
			randNum = (randNum + 1)% virtualArrayList.length;
		}
		
		for(Map.Entry<String, String> entry : R2V_map.entrySet()){
			V2R_map.put(entry.getValue(), entry.getKey());
		}
		//OFSwitchManager switchDetails = new OFSwitchManager();
		//Map<DatapathId, IOFSwitch> Itr = switchDetails.getAllSwitchMap();
//		if(Itr!=null){
//			while(Itr.iterator().hasNext()){
//				clearFlowMods(Itr.iterator().next());
//			}
//		}
		
	
	}
	
	public static void clearFlowMods(IOFSwitch sw){
		Match match = sw.getOFFactory().buildMatch().build();
		OFFlowDelete fm = sw.getOFFactory().buildFlowDelete().setMatch(match).build();
		try {
			sw.write(fm);
		} catch (Exception e){
			System.out.println("Failed to clear flows on switch"+ e);
		}
	}


	@Override
	public void run() {
		// TODO Auto-generated method stub
		while(true){
			try{
				Thread.sleep(60000L);
				updateResources();
			} catch(InterruptedException e){
				e.printStackTrace();
			}
		}
	}
	

}
