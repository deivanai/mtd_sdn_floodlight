package net.floodlightcontroller.mtd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Random;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
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
import net.floodlightcontroller.core.internal.OFSwitchManager;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;

public class mtd implements IFloodlightModule, IOFMessageListener, Runnable {

	protected IFloodlightProviderService floodlightProvider;
	protected IRoutingService routingProvider;
	protected static IOFSwitchService switchService;
	protected IDeviceService deviceService;
	protected static OFSwitchManager switchDetails;

	protected static Logger logger;
	static Map<String, String> R2V_map = new HashMap<String, String>();// real
																		// to
																		// virtual
																		// IP
																		// address
																		// map
	static Map<String, String> V2R_map = new HashMap<String, String>();// virtual
																		// to
																		// real
																		// IP
																		// address
																		// map
	Map<String, String> host_map = new HashMap<String, String>();// real ip
																	// address
																	// to switch
																	// ip map
	Table<String, String, OFPort> host_switch_port_map = HashBasedTable
			.create();
	static ArrayList<String> virtualIPList = new ArrayList<String>(); // pool for virtual IP
	ArrayList<String> datapath = new ArrayList<String>(); // list of switch ids
	Map<String, String> authorized_pair = new HashMap<String, String>();// authorized
																		// IPs
																		// in
																		// pairs
	
	@Override
	public String getName() {
		return "MTD";
	}

	public mtd() {
		String timerEventGen = "TimerEventGen";
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
		// make sure this listener is called before default forwarding module to
		// make sure overrides taken to forward/ packet drop works fine.
		return (type.equals(OFType.PACKET_IN) && (name.equals("forwarding")));

	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		OFPacketIn packetIn = (OFPacketIn) msg;
		OFPort inPort = packetIn.getMatch().get(MatchField.IN_PORT);
		OFPort outPort = OFPort.FLOOD; // default set to flood for packet out.
		Boolean pktDrop = false;
		Boolean authorizedPair = false;
		DatapathId switchId = sw.getId();
		String switchid_str = switchId.toString();

		OFActions ofActions = sw.getOFFactory().actions();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFOxms oxms = sw.getOFFactory().oxms();
		ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		OFInstructions instructions = sw.getOFFactory().instructions();
		Match.Builder mb = sw.getOFFactory().buildMatch();

		IPv4Address dest_ip = null, source_ip = null;
		String destip_str = null, sourceip_str = null;
		EthType eth_type = null;
		MacAddress source_mac = null, dest_mac = null;

		logger.debug("Current Switch: " + switchid_str);

		if (eth.getEtherType() == EthType.ARP) {
			eth_type = EthType.ARP;
			ARP arp = (ARP) eth.getPayload();
			dest_ip = arp.getTargetProtocolAddress();
			source_ip = arp.getSenderProtocolAddress();
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
			source_mac = eth.getSourceMACAddress();
			dest_mac = eth.getDestinationMACAddress();

			logger.info("packet In message for ARP  dst: " + destip_str
					+ " , source : " + source_ip.toString());
			logger.info("source mac: " + source_mac.toString() + " dest mac: "
					+ dest_mac.toString());

			// handle changing virtual to real ip for destination if its final
			// hop/ or not known
			if (isVirtualIPAddress(destip_str)) {
				String rdestip_str = V2R_map.get(destip_str);
				logger.info("check if switch port is known "
						+ host_switch_port_map.toString());
				if (host_switch_port_map.contains(rdestip_str, switchid_str)) {
					// out port to specific port if dest ip's corresponding port
					// is already known.
					outPort = host_switch_port_map.get(rdestip_str,
							switchid_str);
					logger.info("for dest ip: " + rdestip_str
							+ " port already known: " + outPort.toString());
				}
				if (isDirectContact(switchid_str, rdestip_str)) {
					logger.info("convert to real dest ip if host is attached to current switch ");
					logger.info(destip_str + " => " + rdestip_str
							+ " attached to: " + switchid_str);
					// # add a packet out send with real destination address
					// swapped
					IPv4Address rdestip = IPv4Address.of(rdestip_str);
					OFActionSetField setDestIP = ofActions
							.buildSetField()
							.setField(
									oxms.buildArpTpa().setValue(rdestip)
											.build()).build();
					actionList.add(setDestIP);
				}
			}
			// if source ip is real, swap it to virtual ip for all cases.
			if (isRealIPAddress(sourceip_str)) {
				// learn the in port for any source ip for future use and avoid
				// flooding.
				if (!host_map.containsKey(sourceip_str)) {
					logger.info("learn host map  IP attached to switch: "
							+ sourceip_str + "attached to: " + switchid_str);
					host_map.put(sourceip_str, switchid_str);
					host_switch_port_map
							.put(sourceip_str, switchid_str, inPort);
				}
				String vsourceip_str = R2V_map.get(sourceip_str);
				logger.info(sourceip_str + " changed to => " + vsourceip_str);
				// add action to send with real source address swapped to
				// virtual map.
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
				OFActionSetField setSourceIP = ofActions
						.buildSetField()
						.setField(
								oxms.buildArpSpa().setValue(vsourceip).build())
						.build();
				actionList.add(setSourceIP);
			}
			eth.setPayload(arp);
			mb.setExact(MatchField.IN_PORT, inPort)
					.setExact(MatchField.ETH_TYPE, eth_type)
					.setExact(MatchField.ARP_SPA, source_ip)
					.setExact(MatchField.ARP_TPA, dest_ip).build();
		}

		if (eth.getEtherType() == EthType.IPv4) {
			eth_type = EthType.IPv4;
			IPv4 ipv4 = (IPv4) eth.getPayload();
			dest_ip = ipv4.getDestinationAddress();
			source_ip = ipv4.getSourceAddress();
			destip_str = dest_ip.toString();
			sourceip_str = source_ip.toString();
			source_mac = eth.getSourceMACAddress();
			dest_mac = eth.getDestinationMACAddress();

			logger.info("packet In message for ICMP for destination: "
					+ destip_str + " source ip: " + sourceip_str);

			if (isVirtualIPAddress(destip_str)) {
				String rdestip_str = V2R_map.get(destip_str);
				if (host_switch_port_map.contains(rdestip_str, switchid_str)) {
					// out port to specific port if dest ip's corresponding port
					// is already known.
					outPort = host_switch_port_map.get(rdestip_str,
							switchid_str);
					logger.info("for dest ip: " + rdestip_str
							+ " port already known: " + outPort.toString());
				}
				if (isDirectContact(switchid_str, rdestip_str)) {
					logger.info("convert if host is directly attached"
							+ destip_str + " => " + V2R_map.get(destip_str));
					IPv4Address rdestip = IPv4Address.of(rdestip_str);

					OFActionSetField setDstIp = ofActions
							.buildSetField()
							.setField(
									oxms.buildIpv4Dst().setValue(rdestip)
											.build()).build();
					actionList.add(setDstIp);
				}
			}
			if (isRealIPAddress(sourceip_str)) {
				logger.info(sourceip_str + " => " + R2V_map.get(sourceip_str));
				// learn the in port for any source ip address for future use
				// and avoid flooding.
				if (!host_map.containsKey(sourceip_str)) {
					logger.info("learn host map  IP attached to switch: "
							+ source_ip.toString() + "attached to: "
							+ switchid_str);
					host_map.put(sourceip_str, switchid_str);
					host_switch_port_map
							.put(sourceip_str, switchid_str, inPort);
				}

				String vsourceip_str = R2V_map.get(sourceip_str);
				// add action to send with real dest address swapped
				IPv4Address vsourceip = IPv4Address.of(vsourceip_str);
				OFActionSetField setSourceIp = ofActions
						.buildSetField()
						.setField(
								oxms.buildIpv4Src().setValue(vsourceip).build())
						.build();
				actionList.add(setSourceIp);
			}
			eth.setPayload(ipv4);
			mb.setExact(MatchField.IN_PORT, inPort)
					.setExact(MatchField.ETH_TYPE, eth_type)
					.setExact(MatchField.IPV4_DST, dest_ip)
					.setExact(MatchField.IPV4_SRC, source_ip)
					.setExact(MatchField.ETH_SRC, source_mac)
					.setExact(MatchField.ETH_DST, dest_mac).build();
		}
		if (isRealIPAddress(destip_str) && isRealIPAddress(sourceip_str)) {
			if (host_switch_port_map.contains(destip_str, switchid_str)
					&& host_switch_port_map
							.contains(sourceip_str, switchid_str)) {
				logger.info("source and destination are in same switch, allow packet both of them are real ip");
				return Command.CONTINUE; // let default forwarding flow takes
											// care.dont do anything with MTD.
			}
			if (isAuthorizedPair(sourceip_str, destip_str)) {
				authorizedPair = true;
				logger.info("authorized ip access , allow packet without changing any IP address ");
				if (host_map.containsKey(sourceip_str)
						&& host_map.containsKey(destip_str)) {
					DatapathId src_datapathid = DatapathId.of(host_map
							.get(sourceip_str));
					DatapathId dest_datapathid = DatapathId.of(host_map
							.get(destip_str));
					OFPort endPort = host_switch_port_map.get(destip_str,
							dest_datapathid.toString());
					this.AddFlowRulesInRoute(src_datapathid, dest_datapathid,
							source_ip, dest_ip, eth.getEtherType(), inPort,
							endPort, authorizedPair);
				}
			} else {
				logger.info("illegitimate access drop packet: " + sourceip_str
						+ " => " + destip_str);
				pktDrop = true;
				outPort = OFPort.ZERO; // assigning to random port that we don't
										// use here.
				actionList.clear(); // clear all actions so that packet will be
									// dropped.
				return Command.STOP;
				// actionlist will be empty in this case to drop the packet.
			}
		}
		if (!pktDrop) {
			// add output action to port if packet should not be dropped.
			OFActionOutput output = ofActions.buildOutput()
					.setMaxLen(0xFFffFFff).setPort(outPort).build();
			actionList.add(output);

			// if both the target switch and source switch are known
			// lets calculate route and install flow rules all throughout the
			// switches
			// source ip is real, destip is virtual
			if (host_map.containsKey(sourceip_str)
					&& host_map.containsKey(V2R_map.get(destip_str))) {
				logger.info("lets print out the route calculated by topology manager");
				DatapathId src_datapathid = DatapathId.of(host_map
						.get(sourceip_str));
				DatapathId dest_datapathid = DatapathId.of(host_map.get(V2R_map
						.get(destip_str)));

				OFPort endPort = host_switch_port_map.get(
						V2R_map.get(destip_str), dest_datapathid.toString());
				this.AddFlowRulesInRoute(src_datapathid, dest_datapathid,
						source_ip, dest_ip, eth.getEtherType(), inPort,
						endPort, false);
			}
		}
		if (outPort != OFPort.FLOOD) {
			// add flow rules if output port is known.
			OFInstructionApplyActions instructionsApplyAction = instructions
					.buildApplyActions().setActions(actionList).build();
			instructionList.add(instructionsApplyAction);

			OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
					.setBufferId(OFBufferId.NO_BUFFER).setHardTimeout(3600)
					.setIdleTimeout(10).setPriority(200)
					.setTableId(TableId.of(0)).setMatch(mb.build())
					.setInstructions(instructionList).build();

			logger.info("flow add: " + flowAdd.toString());
			sw.write(flowAdd);
		}
		OFPacketOut packetOut = sw.getOFFactory().buildPacketOut()
				.setData(eth.serialize()).setActions(actionList)
				.setInPort(inPort).build();

		logger.debug("packet out: " + packetOut.toString());
		sw.write(packetOut);

		return Command.CONTINUE;
	}

	// used to add flow rules if there are multiple hops.
	private void AddFlowRulesInRoute(DatapathId src_datapathid,
			DatapathId dest_datapathid, IPv4Address source_ip,
			IPv4Address dest_ip, EthType ethType, OFPort inPort,
			OFPort outPort, boolean authorizedPair) {

		if (routingProvider.routeExists(src_datapathid, dest_datapathid)) {
			Route route = routingProvider.getRoute(src_datapathid, inPort,
					dest_datapathid, outPort, U64.of(0));
			List<NodePortTuple> nodePortList = route.getPath();
			logger.info("route for switches: " + src_datapathid.toString()
					+ " => " + dest_datapathid.toString());
			logger.info("route calculated: " + nodePortList.toString());
			logger.info("authorized user " + String.valueOf(authorizedPair));
			// each node pair is taken to add flow rule at input switch. hence
			// np = np+2 .
			for (int np = 0; np < nodePortList.size() - 1; np = np + 2) {
				logger.info("node: " + nodePortList.get(np).toString());
				// get switch object for current node pair.
				IOFSwitch sw = switchService.getSwitch(nodePortList.get(np)
						.getNodeId());
				logger.info("current switch to flow add: " + sw.toString());
				OFActions ofActions = sw.getOFFactory().actions();
				ArrayList<OFAction> actionList = new ArrayList<OFAction>();
				ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
				OFInstructions instructions = sw.getOFFactory().instructions();
				OFOxms oxms = sw.getOFFactory().oxms();
				Match.Builder mb = sw.getOFFactory().buildMatch();
				OFPort input_port = nodePortList.get(np).getPortId();
				if (ethType == EthType.ARP) {
					mb.setExact(MatchField.IN_PORT, input_port)
							.setExact(MatchField.ETH_TYPE, ethType)
							.setExact(MatchField.ARP_TPA, dest_ip)
							.setExact(MatchField.ARP_SPA, source_ip).build();
					// source node, change the source ip.
					if ((np == 0) && (!authorizedPair)) {
						OFActionSetField setSourceIp = ofActions
								.buildSetField()
								.setField(
										oxms.buildArpSpa()
												.setValue(
														IPv4Address.of(R2V_map.get(source_ip
																.toString())))
												.build()).build();
						actionList.add(setSourceIp);
						// change the source ip value for consecutive nodes.
						source_ip = IPv4Address.of(R2V_map.get(source_ip
								.toString()));
					}
					// end node, change the dest ip to real ip
					if ((np == nodePortList.size() - 2) && (!authorizedPair)) {
						OFActionSetField setDstIp = ofActions
								.buildSetField()
								.setField(
										oxms.buildArpTpa()
												.setValue(
														IPv4Address.of(V2R_map.get(dest_ip
																.toString())))
												.build()).build();
						actionList.add(setDstIp);
					}
				} else if (ethType == EthType.IPv4) { // ICMP packet
					mb.setExact(MatchField.IN_PORT, input_port)
							.setExact(MatchField.ETH_TYPE, ethType)
							.setExact(MatchField.IPV4_DST, dest_ip)
							.setExact(MatchField.IPV4_SRC, source_ip).build();

					if ((np == 0) && (!authorizedPair)) {
						OFActionSetField setSourceIp = ofActions
								.buildSetField()
								.setField(
										oxms.buildIpv4Src()
												.setValue(
														IPv4Address.of(R2V_map.get(source_ip
																.toString())))
												.build()).build();
						actionList.add(setSourceIp);
						source_ip = IPv4Address.of(R2V_map.get(source_ip
								.toString()));

					}
					if ((np == nodePortList.size() - 2) && (!authorizedPair)) {
						OFActionSetField setDstIp = ofActions
								.buildSetField()
								.setField(
										oxms.buildIpv4Dst()
												.setValue(
														IPv4Address.of(V2R_map.get(dest_ip
																.toString())))
												.build()).build();
						actionList.add(setDstIp);
					}
				}
				// set the output port for the current processing node pair.

				OFActionOutput output = ofActions.buildOutput()
						.setMaxLen(0xFFffFFff)
						.setPort(nodePortList.get(np + 1).getPortId()).build();
				actionList.add(output);

				OFInstructionApplyActions instructionsApplyAction = instructions
						.buildApplyActions().setActions(actionList).build();
				instructionList.add(instructionsApplyAction);
				OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
						.setBufferId(OFBufferId.NO_BUFFER).setHardTimeout(3600)
						.setIdleTimeout(10).setPriority(100)
						.setTableId(TableId.of(0)).setMatch(mb.build())
						.setInstructions(instructionList).build();
				logger.info("flow add for route: " + flowAdd.toString());
				sw.write(flowAdd);
			}

		}

		else {
			logger.info("no route exists for now, just add in source data path id as default flow");
			logger.info("could be source and dest are attached to same host");
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
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRoutingService.class);
		l.add(IOFSwitchService.class);
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {

		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		routingProvider = context.getServiceImpl(IRoutingService.class);
		logger = LoggerFactory.getLogger(mtd.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);

		/*for (int i = 0; i < 16; i++) {
			R2V_map.put("10.0.0." + Integer.toString(i + 1), "10.0.0."
					+ Integer.toString(i + 65));
			V2R_map.put("10.0.0." + Integer.toString(i + 65), "10.0.0."
					+ Integer.toString(i + 1));
		}*/
		authorized_pair.put("10.0.0.2", "10.0.0.8");
		authorized_pair.put("10.0.0.8", "10.0.0.2");
		for( int i = 65;i<255;i++){
			virtualIPList.add("10.0.0." + String.valueOf(i));
		}
		for(int i= 1;i < 16;i++){
			R2V_map.put("10.0.0." + String.valueOf(i),"");// no virtual mapping at init
		}
		logger.info("init");
        updateResources();

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

	private boolean isRealIPAddress(String ipAddress) {
		if (R2V_map.containsKey(ipAddress))
			return true;
		else
			return false;
	}

	private boolean isVirtualIPAddress(String ipAddress) {
		if (V2R_map.containsKey(ipAddress))
			return true;
		else
			return false;
	}

	private boolean isDirectContact(String dataPath, String ipAddress) {
		logger.info("host map: " + host_map.toString());
		logger.info("port map " + host_switch_port_map.toString());
		if (host_map.containsKey(ipAddress)) {
			if (host_map.get(ipAddress).equals(dataPath))
				return true;
			else
				return false;
		}
		return true; // return true if host is not found in host map
					 // while mtd is still learning to proceed further.
	}

	private boolean isAuthorizedPair(String sourceIpAddress,
			String destIpAddress) {
		boolean authorizedPair = false;
		logger.info("check is authorized pair:" + sourceIpAddress + " "
				+ destIpAddress);
		if (authorized_pair.containsKey(sourceIpAddress)) {
			authorizedPair = authorized_pair.get(sourceIpAddress).equals(
					destIpAddress);
			logger.info(String.valueOf(authorizedPair));
		}
		return authorizedPair;
	}

	private static void updateResources() {
		// update the mapping of real and virtual ip addresses
		// clear flow rules
		// add default entry to switches
		Random rand = new Random();
		int randNum = 0;
	    ArrayList<Integer> randIndex = new ArrayList<Integer>();
		for (String key : R2V_map.keySet()) {
			do{
				
				randNum = rand.nextInt(virtualIPList.size());
			}while (randIndex.contains(randNum));
			randIndex.add(randNum);
			R2V_map.put(key, virtualIPList.get(randNum));
		}
		logger.info("Real to Virtual IP map:");
		logger.info(R2V_map.toString());
		for (Map.Entry<String, String> entry : R2V_map.entrySet()) {
			V2R_map.put(entry.getValue(), entry.getKey());
		}
	}

	private static void resetFlowTableEntries() {
		Map<DatapathId, IOFSwitch> switches_map = switchService
				.getAllSwitchMap();
		for (Map.Entry<DatapathId, IOFSwitch> sw_map : switches_map.entrySet()) {
			//DatapathId sw_id = sw_map.getKey();
			IOFSwitch sw = sw_map.getValue();
			clearFlowMods(sw);
			addFlowTableMissEntry(sw);
		}

	}

	private static void addFlowTableMissEntry(IOFSwitch sw) {
		OFActions ofActions = sw.getOFFactory().actions();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		OFInstructions instructions = sw.getOFFactory().instructions();

		OFActionOutput output = ofActions.buildOutput().setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER).build();
		actionList.add(output);

		OFInstructionApplyActions instructionsApplyAction = instructions
				.buildApplyActions().setActions(actionList).build();
		instructionList.add(instructionsApplyAction);

		OFFlowAdd defaultFlow = sw.getOFFactory().buildFlowAdd()
				.setTableId(TableId.of(0)).setPriority(0)
				.setInstructions(instructionList).build();
		logger.info("add flow table miss enty for switch: "
				+ sw.getId().toString());
		logger.info(defaultFlow.toString());
		sw.write(defaultFlow);
	}

	private static void clearFlowMods(IOFSwitch sw) {
		logger.info("Deleting Flow Rules for switch: " + sw.getId().toString());
		Match match = sw.getOFFactory().buildMatch().build();
		OFFlowDelete fm = sw.getOFFactory().buildFlowDelete().setMatch(match)
				.build();
		try {
			sw.write(fm);
		} catch (Exception e) {
			logger.info("Failed to clear flows on switch" + e);
		}
		logger.info(fm.toString());
	}

	@Override
	public void run() {
		// run the thread that expires periodically to update real to virtual
		// map and clear flow table entries.
		while (true) {
			try {
				Thread.sleep(30000L);
				updateResources();
				resetFlowTableEntries();
			} catch (InterruptedException e) {
				logger.info("thread interrupted", e.toString());
			}
		}
	}

}
