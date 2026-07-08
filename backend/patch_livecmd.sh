sed -i 's/Pcap.DISPATCH_BUFFER_FULL/Pcap.LOOP_INFINITE/g' /mnt/extra_storage/IDS_Project/CICFlowMeter_V3/src/main/java/cic/cs/unb/ca/ifm/LiveCmd.java

sed -i 's/flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, true));/try {\n                flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, true));\n            } catch (Exception e) {\n                logger.debug("Skipped packet due to error: " + e.getMessage());\n            }/g' /mnt/extra_storage/IDS_Project/CICFlowMeter_V3/src/main/java/cic/cs/unb/ca/ifm/LiveCmd.java
