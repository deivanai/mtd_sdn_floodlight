package net.floodlightcontroller.mtd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
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
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packetstreamer.thrift.Packet;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;


public class mtd implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider;
	protected IRoutingService routingProvider;
	protected IOFSwitchService switchService;
	protected static Logger logger;
	Map<String,String> R2V_map = new HashMap<String,String>();// real to virtual IP address map
    Map<String,String> V2R_map = new HashMap<String,String>();// virtual to real IP address map 
	Map<String,String> host_map = new HashMap<String,String>();// real ip address to switch ip map
	Table<String,String,OFPort>host_switch_port_map = HashBasedTable.create();
	ArrayList<String> datapath = new ArrayList<String> (); // list of switch ids 
	@Override
	public String getName() {
		return "MTD";
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
        Boolean pktDrop = false;
        DatapathId switchId = sw.getId();
        String switchid_str = switchId.toString();
        OFActions ofActions = sw.getOFFactory().actions();
		ArrayList<OFAction> actionList = new ArrayList<OFAction> ();               	
		OFOxms oxms = sw.getOFFactory().oxms();
		ArrayList<OFInstruction>  instructionList = new ArrayList<OFInstruction>(); 
		
		OFInstructions instructions = sw.getOFFactory().instructions();		
		Match.Builder mb = sw.getOFFactory().buildMatch();
		
		IPv4Address dest_ip = null , source_ip = null;
		String destip_str = null, sourceip_str = null;
		EthType eth_type = null;
		MacAddress source_mac, dest_mac;
		logger.info("Current Switch " + switchid_str);
		if(eth.getEtherType() == EthType.ARP) {
			eth_type = EthType.ARP;
			ARP arp = (ARP) eth.getPayload();
			dest_ip = arp.getTargetProtocolAddress();
			source_ip = arp.getSenderProtocolAddress();		
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
			source_mac = eth.getSourceMACAddress();
			dest_mac = eth.getDestinationMACAddress();
					    
			logger.info("packet In message for ARP  dst: " + destip_str + " , source : " + source_ip.toString());
			logger.info("source mac: " + source_mac.toString()+ " dest mac: " + dest_mac.toString());
			
			
			if (V2R_map.containsKey(destip_str) ) {
				String rdestip_str = V2R_map.get(destip_str);
				logger.info("check if host switch port map added " + host_switch_port_map.toString());
				if(host_switch_port_map.contains(rdestip_str, switchid_str))
		        {
		        	// out port to specific port if dest ip's corresponding port is already known.
					outPort = host_switch_port_map.get(rdestip_str,switchid_str);      
					logger.info("for dest ip: " + rdestip_str + " port already known: " + outPort.toString());
			    }

				if(isDirectContact(switchid_str,rdestip_str)){
					logger.info("convert to real dest ip if host is attached to current switch " );
					logger.info(destip_str + " => " + rdestip_str + " attached to: " + switchid_str);
					// # add a packet out send with real destination address swapped 
					IPv4Address rdestip = IPv4Address.of(rdestip_str);			  
					//arp.setTargetProtocolAddress(rdestip);	
					OFActionSetField setDestIP = ofActions.buildSetField()
							.setField(oxms.buildArpTpa().setValue(rdestip).build()).build();
				    actionList.add(setDestIP);

				}
			}
			if(R2V_map.containsKey(destip_str)){
				// fix add packet drop case in case some one is trying to ping with real ip dest address 
				//pktDrop = true;
			}
			if(R2V_map.containsKey(sourceip_str)){
				//learn the in port for any source ip for future use and avoid flooding. 
		        if(!host_map.containsKey(sourceip_str)){
		        	logger.info("learn host map  IP attached to switch: " + sourceip_str  +  "attached to: " + switchid_str );				
					host_map.put(sourceip_str, switchid_str);
					host_switch_port_map.put(sourceip_str, switchid_str, inPort);	        	       
		        }
		        
				String vsourceip_str = R2V_map.get(sourceip_str);   
				logger.info(sourceip_str + " changed to => " + vsourceip_str);
				//add a packet out send with real dest address swapped 
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
				//arp.setSenderProtocolAddress(vsourceip);	
				OFActionSetField setSourceIP = ofActions.buildSetField()
						.setField(oxms.buildArpSpa().setValue(vsourceip).build()).build();
			    actionList.add(setSourceIP);
			
			}
			
			eth.setPayload(arp);
			mb.setExact(MatchField.IN_PORT, inPort)
		    		.setExact(MatchField.ETH_TYPE, eth_type )
		    		.setExact(MatchField.ARP_SPA, source_ip)
		    		.setExact(MatchField.ARP_TPA, dest_ip)
		    		.build();

     	}
		
		if(eth.getEtherType() == EthType.IPv4) {
			eth_type = EthType.IPv4;
			IPv4   ipv4 = (IPv4) eth.getPayload();
			dest_ip = ipv4.getDestinationAddress();
			source_ip = ipv4.getSourceAddress();
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
	        source_mac = eth.getSourceMACAddress();
	        dest_mac = eth.getDestinationMACAddress();
	        logger.info("packet In message for ICMP for destination: " + destip_str + " source ip: "+ sourceip_str);
				
			if (V2R_map.containsKey(destip_str)){
				String rdestip_str = V2R_map.get(destip_str);  
				
				if(isDirectContact(switchid_str,rdestip_str)){
					logger.info("convert if host is directly attached" + destip_str + " => "  + V2R_map.get(destip_str) );
					IPv4Address rdestip = IPv4Address.of(rdestip_str);
					
					OFActionSetField setDstIp = ofActions.buildSetField()
						.setField(oxms.buildIpv4Dst().setValue(rdestip).build())
						.build();
					actionList.add(setDstIp);
					//ipv4.setDestinationAddress(rdestip);
			
				}
				if(host_switch_port_map.contains(rdestip_str, switchid_str))
				{
					// out port to specific port if dest ip's corresponding port is already known.
					outPort = host_switch_port_map.get(rdestip_str,switchid_str);
					logger.info("for dest ip: " + rdestip_str + " port already known: " + outPort.toString() );					
				}
			
			}
			if(R2V_map.containsKey(sourceip_str)){
				logger.info(sourceip_str + " => " + R2V_map.get(sourceip_str));
				//learn the in port for any source ip address for future use and avoid flooding. 
		        
				if(!host_map.containsKey(sourceip_str)){
					logger.info("learn host map  IP attached to switch: " + source_ip.toString()  +  "attached to: " + switchid_str );				
					host_map.put(sourceip_str, switchid_str);
					host_switch_port_map.put(sourceip_str, switchid_str, inPort);
			        
				}
				
				String vsourceip_str = R2V_map.get(sourceip_str);   
				//add a packet out send with real dest address swapped 
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
			    //ipv4.setSourceAddress(vsourceip);
				OFActionSetField setSourceIp = ofActions.buildSetField()
						.setField(oxms.buildIpv4Src().setValue(vsourceip).build())
						.build();
				actionList.add(setSourceIp);	
			}			      
			eth.setPayload(ipv4);

			mb.setExact(MatchField.IN_PORT, inPort)
			    		.setExact(MatchField.ETH_TYPE, eth_type )
			    		.setExact(MatchField.IPV4_DST, dest_ip)
			    		.setExact(MatchField.IPV4_SRC, source_ip)
			    		.setExact(MatchField.ETH_SRC, source_mac)
			    		.setExact(MatchField.ETH_DST,dest_mac)
			    		.build();	

		}
	
	    if(!pktDrop){
	    	
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
		   	//if both the target switch and source switch are known,  at source of packet IN from source switch are known
		   	//lets calculate route and install flow rules all throughout the switches 
		   	if(host_map.containsKey(sourceip_str) && host_map.containsKey(V2R_map.get(destip_str))){
	        	logger.info("lets print out the route calculated by topology manager");
	        	DatapathId src_datapathid = DatapathId.of(host_map.get(sourceip_str));
	        	DatapathId dest_datapathid = DatapathId.of(host_map.get(V2R_map.get(destip_str)));
	        	//source ip is real, destip is virtual 
	        	OFPort endPort = host_switch_port_map.get(V2R_map.get(destip_str), dest_datapathid.toString());
	        	this.AddFlowRulesInRoute(src_datapathid, dest_datapathid, source_ip, dest_ip, eth.getEtherType(),inPort, endPort);
		   	}
		   	else if(outPort!= OFPort.FLOOD){
		   		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
		    		.setBufferId(OFBufferId.NO_BUFFER) // TODO handle fix BufferId later
		    		.setHardTimeout(3600)
		    		.setIdleTimeout(10)
		    		.setPriority(200)
		    		.setTableId(TableId.of(0))
		    		.setMatch(mb.build())
		    		.setInstructions(instructionList)
		    		.build();
		    
		   		logger.info("flow add: " + flowAdd.toString());
		   		sw.write(flowAdd);
		   	}	
		   	OFPacketOut packetOut = sw.getOFFactory().buildPacketOut()
		   				.setData(eth.serialize())
		   				.setActions(actionList)
		   				.setInPort(inPort)
		   				.build();
	     
		   	logger.info("packet out: " + packetOut.toString());
		   		sw.write(packetOut);	    
	    }
		
	    return Command.CONTINUE;
	}

	private void AddFlowRulesInRoute(DatapathId src_datapathid,
			DatapathId dest_datapathid, IPv4Address source_ip, IPv4Address dest_ip, EthType ethType, OFPort inPort, OFPort outPort) {
        // will add flow rules leaving out the source and destination for simple output with match
		if(routingProvider.routeExists(src_datapathid, dest_datapathid)){
			Route route = routingProvider.getRoute(src_datapathid, inPort,dest_datapathid,outPort,U64.of(0));
			List<NodePortTuple> nodePortList = route.getPath();
			logger.info(src_datapathid.toString() + " => " + dest_datapathid.toString());
			logger.info(nodePortList.toString());
			/*NodePortTuple sourceNode,destNode;
			sourceNode = new NodePortTuple(src_datapathid,inPort); 
			nodePortList.add(0,sourceNode);
			// change the destination node from FLOOD to correct output port
			destNode = new NodePortTuple(dest_datapathid, outPort);
			nodePortList.add(nodePortList.size(), destNode);
			logger.info("after adding source and end port\n");
			logger.info(nodePortList.toString());*/
			for(int np=0; np < nodePortList.size()-1 ; np = np+2){
				logger.info("node: " + nodePortList.get(np).toString());
				IOFSwitch sw = switchService.getSwitch(nodePortList.get(np).getNodeId());
				logger.info("current switch to flow add: " + sw.toString());
				OFActions ofActions = sw.getOFFactory().actions();
				ArrayList<OFAction> actionList = new ArrayList<OFAction> ();               	
				ArrayList<OFInstruction>  instructionList = new ArrayList<OFInstruction>(); 
				OFInstructions instructions = sw.getOFFactory().instructions();
				OFOxms oxms = sw.getOFFactory().oxms();
				Match.Builder mb = sw.getOFFactory().buildMatch();
				OFPort input_port = nodePortList.get(np).getPortId();
	            if(ethType == EthType.ARP){
	            	mb.setExact(MatchField.IN_PORT, input_port)
	            		.setExact(MatchField.ETH_TYPE, ethType)
	            		.setExact(MatchField.ARP_TPA, dest_ip)
	            		.setExact(MatchField.ARP_SPA, source_ip)
	            		.build();
	            	
	            	if(np==0){
						OFActionSetField setSourceIp = ofActions.buildSetField()
								.setField(oxms.buildArpSpa().setValue(IPv4Address.of(R2V_map.get(source_ip.toString()))).build())
								.build();
						actionList.add(setSourceIp);
						source_ip = IPv4Address.of(R2V_map.get(source_ip.toString()));
					}
					//end node, change the dest ip to real ip 
					if(np == nodePortList.size()-2){
						OFActionSetField setDstIp = ofActions.buildSetField()
								.setField(oxms.buildArpTpa().setValue(IPv4Address.of(V2R_map.get(dest_ip.toString()))).build())
								.build();
							actionList.add(setDstIp);
					}
	            }
	            else{
	            	mb.setExact(MatchField.IN_PORT, input_port)
            			.setExact(MatchField.ETH_TYPE, ethType)
            			.setExact(MatchField.IPV4_DST, dest_ip)
            			.setExact(MatchField.IPV4_SRC, source_ip)
            			.build();
	            
	            	if(np==0){
						OFActionSetField setSourceIp = ofActions.buildSetField()
								.setField(oxms.buildIpv4Src().setValue(IPv4Address.of(R2V_map.get(source_ip.toString()))).build())
								.build();
						actionList.add(setSourceIp);
						source_ip = IPv4Address.of(R2V_map.get(source_ip.toString()));
						
					}
					//end node, change the dest ip to real ip 
					if(np == nodePortList.size()-2){
						OFActionSetField setDstIp = ofActions.buildSetField()
								.setField(oxms.buildIpv4Dst().setValue(IPv4Address.of(V2R_map.get(dest_ip.toString()))).build())
								.build();
							actionList.add(setDstIp);
					}
	            }
				//starting node change the source ip to virtual id
				
				OFActionOutput output = ofActions.buildOutput()
		       			.setMaxLen(0xFFffFFff)
		       			.setPort(nodePortList.get(np+1).getPortId()) // output for that node pair
		       			.build();
			    actionList.add(output);		   
				
			    OFInstructionApplyActions instructionsApplyAction = instructions
			    		.buildApplyActions()
			    		.setActions(actionList)
			    		.build();
			   	instructionList.add(instructionsApplyAction);	    
			   	OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
			    		.setBufferId(OFBufferId.NO_BUFFER) // TODO handle fix BufferId later
			    		.setHardTimeout(3600)
			    		.setIdleTimeout(10)
			    		.setPriority(100)
			    		.setTableId(TableId.of(0))
			    		.setMatch(mb.build())
			    		.setInstructions(instructionList)
			    		.build();
			   	logger.info("flow add for route: " + flowAdd.toString());
			   	sw.write(flowAdd);
			}
			    				
		}
		else {
			logger.info("no route exists for now, just add in source data path as default flow");
		//eRoute [id=RouteId [src=00:00:00:00:00:00:00:04 dst=00:00:00:00:00:00:00:03], switchPorts=[[id=00:00:00:00:00:00:00:04, port=1], [id=00:00:00:00:00:00:00:03, port=2]]]
		}
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
		l.add(IRoutingService.class);
		l.add(IOFSwitchService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		routingProvider = context.getServiceImpl(IRoutingService.class);
		logger = LoggerFactory.getLogger(mtd.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		
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
		logger.info("host map: " + host_map.toString());
		logger.info("port map " + host_switch_port_map.toString());
		if(host_map.containsKey(ipAddress)) {
		    if(host_map.get(ipAddress).equals(dataPath))
		    	return true;
		    else
		    	return false;
		}
		return true; // return true if host is not found in host map to proceed further.  
	}
	
	

}
