package net.floodlightcontroller.mtd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packetstreamer.thrift.Packet;



public class mtd implements IFloodlightModule, IOFMessageListener {

	
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	Map<String,String> R2V_map = new HashMap<String,String>();
    Map<String,String> V2R_map = new HashMap<String,String>();
	Map<String,String> host_map = new HashMap<String,String>();
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
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
		if(eth.getEtherType() == EthType.ARP) {
			ARP arp = (ARP) eth.getPayload();
			IPv4Address dest_ip = arp.getTargetProtocolAddress();
			DatapathId switchId = sw.getId(); 
			String destip_str = dest_ip.toString();
			String switchid_str = switchId.toString();
			String rdestip_str = "";
			if (V2R_map.containsKey(destip_str)) {
			    rdestip_str = V2R_map.get(destip_str);
			    //if host is attached to current switch
                if(host_map.containsKey(rdestip_str)){
                	logger.info(destip_str + " =>" + rdestip_str + "attached to " + switchid_str);
                	 // # add a packet out send with real dest address swapped 
                	IPv4Address rdestip = IPv4Address.of(rdestip_str);
                	OFActions ofActions = sw.getOFFactory().actions();
                	OFOxms oxms = sw.getOFFactory().oxms();
                	
                	OFAction ofAction = ofActions.buildSetField().setField(oxms.ipv4Dst(rdestip)).build();
                	 
                	OFPacketOut packetOut = sw.getOFFactory().buildPacketOut()
                			.setData(eth.serialize())
                			.setActions(Collections.singletonList(ofAction))
                			.setInPort(OFPort.CONTROLLER)
                			.build();
                	sw.write(packetOut);
               	
                }
                else{
                	//TODO to fix if host attachments are not present about unknown hosts 
                }
            }
			else{
				//TODO to add learning of virtual to real maps 
			}
	    }
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
		logger = LoggerFactory.getLogger(mtd.class);

		
		//For now stub the dynamic maps and create a static list to demonstrate routing with virtual address
		   R2V_map.put("10.0.0.1","10.0.0.21");
		   R2V_map.put("10.0.0.2","10.0.0.22");
		   V2R_map.put("10.0.0.21","10.0.0.1");
		   V2R_map.put("10.0.0.22","10.0.0.2");
		   
		   host_map.put("10.0.0.1", "1");
           host_map.put("10.0.0.2", "1");
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

}
