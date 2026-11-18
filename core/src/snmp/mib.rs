//! Built-in names of the standard MIBs (no MIB files to read) and value formatting.

use super::client::Value;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Branch that contains other objects.
    Group,
    /// Single value (instance `.0`).
    Scalar,
    /// Table: the columns sit under `<table>.1`.
    Table,
    /// Column of a table.
    Column,
}

#[derive(Debug, Clone, Copy)]
pub struct Obj {
    pub oid: &'static str,
    pub name: &'static str,
    pub mib: &'static str,
    pub kind: Kind,
    /// Description in Italian; the English one is in `DESCR_EN` (see `description`).
    pub descr: &'static str,
}

impl Obj {
    /// Description in the current language.
    pub fn description(&self) -> &'static str {
        if crate::i18n::is_en() {
            descr_en(self.name).unwrap_or(self.descr)
        } else {
            self.descr
        }
    }
}

/// The UI receives a single `descr` string, chosen by the current language.
impl Serialize for Obj {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = ser.serialize_struct("Obj", 5)?;
        st.serialize_field("oid", self.oid)?;
        st.serialize_field("name", self.name)?;
        st.serialize_field("mib", self.mib)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("descr", self.description())?;
        st.end()
    }
}

/// English description of an object, by name.
fn descr_en(name: &str) -> Option<&'static str> {
    static MAP: OnceLock<std::collections::HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| DESCR_EN.iter().copied().collect())
        .get(name)
        .copied()
}

static DESCR_EN: &[(&str, &str)] = &[
    ("mib-2", "standard objects"),
    ("system", "device identity"),
    ("sysDescr", "description: model and firmware"),
    ("sysObjectID", "device type identifier"),
    ("sysUpTime", "time since the agent started"),
    ("sysContact", "contact person"),
    ("sysName", "device name"),
    ("sysLocation", "physical location"),
    ("sysServices", "network layers served"),
    ("interfaces", "network interfaces"),
    ("ifNumber", "number of interfaces"),
    ("ifTable", "one row per interface"),
    ("ifIndex", "interface number"),
    ("ifDescr", "description"),
    ("ifType", "interface type"),
    ("ifMtu", "maximum packet size"),
    ("ifSpeed", "speed in bit/s (up to 4 Gb/s)"),
    ("ifPhysAddress", "MAC address"),
    ("ifAdminStatus", "status set by the administrator"),
    ("ifOperStatus", "link status"),
    ("ifLastChange", "sysUpTime of the last status change"),
    ("ifInOctets", "bytes received (32 bit)"),
    ("ifInUcastPkts", "unicast packets received"),
    ("ifInDiscards", "received packets discarded"),
    ("ifInErrors", "packets received with errors"),
    ("ifInUnknownProtos", "packets of unknown protocols"),
    ("ifOutOctets", "bytes sent (32 bit)"),
    ("ifOutUcastPkts", "unicast packets sent"),
    ("ifOutDiscards", "outgoing packets discarded"),
    ("ifOutErrors", "packets not sent because of errors"),
    ("ip", "addresses and ARP table"),
    ("ipForwarding", "the device forwards packets (router)"),
    ("ipDefaultTTL", "default TTL"),
    ("ipAddrTable", "IPv4 addresses of the device"),
    ("ipAdEntAddr", "address"),
    ("ipAdEntIfIndex", "interface of the address"),
    ("ipAdEntNetMask", "subnet mask"),
    ("ipAdEntBcastAddr", "least significant bit of the broadcast"),
    ("ipNetToMediaTable", "ARP table (IPv4)"),
    ("ipNetToMediaIfIndex", "interface"),
    ("ipNetToMediaPhysAddress", "MAC address"),
    ("ipNetToMediaNetAddress", "IP address"),
    ("ipNetToMediaType", "dynamic or static"),
    ("ipNetToPhysicalTable", "neighbour table (IPv4 and IPv6)"),
    ("ipNetToPhysicalPhysAddress", "MAC address"),
    ("ipNetToPhysicalType", "dynamic or static"),
    ("ipNetToPhysicalState", "entry state"),
    ("dot1dBridge", "switch: ports and MAC table"),
    ("dot1dBaseBridgeAddress", "MAC address of the switch"),
    ("dot1dBaseNumPorts", "number of ports"),
    ("dot1dBasePortTable", "switch ports"),
    ("dot1dBasePort", "switch port number"),
    ("dot1dBasePortIfIndex", "interface of the port"),
    ("dot1dTpFdbTable", "MAC table (no VLAN)"),
    ("dot1dTpFdbAddress", "MAC address"),
    ("dot1dTpFdbPort", "port where it was seen"),
    ("dot1dTpFdbStatus", "learned or configured"),
    ("qBridgeMIB", "switch with VLANs"),
    ("dot1qTpFdbTable", "MAC table per VLAN"),
    ("dot1qTpFdbPort", "port where it was seen"),
    ("dot1qTpFdbStatus", "learned or configured"),
    ("dot1qVlanStaticTable", "configured VLANs"),
    ("dot1qVlanStaticName", "VLAN name"),
    ("host", "memory, disks, CPU"),
    ("hrSystem", "boot, users and processes"),
    ("hrSystemUptime", "time since the system started"),
    ("hrSystemDate", "system date and time"),
    ("hrSystemNumUsers", "logged-in users"),
    ("hrSystemProcesses", "running processes"),
    ("hrMemorySize", "physical memory in KB"),
    ("hrStorageTable", "disks and memory"),
    ("hrStorageIndex", "number"),
    ("hrStorageType", "type: RAM, disk, network..."),
    ("hrStorageDescr", "description or mount point"),
    ("hrStorageAllocationUnits", "bytes per unit"),
    ("hrStorageSize", "size in units"),
    ("hrStorageUsed", "space used in units"),
    ("hrStorageAllocationFailures", "space requests refused"),
    ("hrDeviceTable", "system devices"),
    ("hrDeviceType", "device type"),
    ("hrDeviceDescr", "description or model"),
    ("hrDeviceStatus", "status"),
    ("hrDeviceErrors", "errors detected by the device"),
    ("hrProcessorTable", "processors"),
    ("hrProcessorLoad", "average load over the last minute (%)"),
    ("hrPrinterTable", "status of the system's printers"),
    ("hrPrinterStatus", "printer status"),
    (
        "hrPrinterDetectedErrorState",
        "detected errors (paper, toner, door)",
    ),
    ("hrSWRunTable", "running processes"),
    ("hrSWRunName", "process name"),
    ("hrSWRunPath", "program path"),
    ("hrSWRunParameters", "start-up parameters"),
    ("hrSWRunType", "type: system, driver, application"),
    ("hrSWRunStatus", "process status"),
    ("hrSWRunPerfTable", "resources used by processes"),
    ("hrSWRunPerfCPU", "CPU time in hundredths of a second"),
    ("hrSWRunPerfMem", "memory used in KB"),
    ("ifMIB", "names, aliases and 64-bit counters"),
    ("ifXTable", "extension of the interface table"),
    ("ifName", "short interface name"),
    ("ifInMulticastPkts", "multicast packets received"),
    ("ifInBroadcastPkts", "broadcast packets received"),
    ("ifOutMulticastPkts", "multicast packets sent"),
    ("ifOutBroadcastPkts", "broadcast packets sent"),
    ("ifHCInOctets", "bytes received, 64-bit counter"),
    ("ifHCOutOctets", "bytes sent, 64-bit counter"),
    ("ifHighSpeed", "speed in Mb/s"),
    ("ifAlias", "description written by the administrator"),
    ("printmib", "printers: trays and supplies"),
    ("prtGeneralTable", "general printer data"),
    ("prtGeneralPrinterName", "printer name"),
    ("prtGeneralSerialNumber", "serial number"),
    ("prtAlertCriticalEvents", "critical alerts since start-up"),
    ("prtAlertAllEvents", "all alerts since start-up"),
    ("prtInputTable", "paper trays"),
    ("prtInputType", "tray type"),
    ("prtInputCapacityUnit", "capacity and level unit"),
    ("prtInputMaxCapacity", "tray capacity"),
    ("prtInputCurrentLevel", "sheets present"),
    ("prtInputMediaName", "paper size"),
    ("prtInputName", "tray name"),
    ("prtMarkerTable", "print units"),
    ("prtMarkerMarkTech", "printing technology"),
    ("prtMarkerCounterUnit", "counter unit"),
    ("prtMarkerLifeCount", "total pages printed"),
    ("prtMarkerPowerOnCount", "pages since last power-on"),
    ("prtMarkerSuppliesTable", "toner and consumables"),
    ("prtMarkerSuppliesMarkerIndex", "print unit served"),
    ("prtMarkerSuppliesColorantIndex", "colorant (0 = none)"),
    ("prtMarkerSuppliesClass", "is consumed or fills up"),
    ("prtMarkerSuppliesType", "supply type"),
    ("prtMarkerSuppliesDescription", "supply description"),
    ("prtMarkerSuppliesSupplyUnit", "unit of measure"),
    ("prtMarkerSuppliesMaxCapacity", "capacity"),
    ("prtMarkerSuppliesLevel", "current level"),
    ("prtMarkerColorantTable", "colorants"),
    ("prtMarkerColorantRole", "colorant role"),
    ("prtMarkerColorantValue", "colour name"),
    ("prtAlertTable", "printer alerts"),
    ("prtAlertSeverityLevel", "alert severity"),
    ("prtAlertTrainingLevel", "who must act"),
    ("prtAlertGroup", "affected part of the printer"),
    ("prtAlertGroupIndex", "number of the affected part"),
    ("prtAlertCode", "alert code"),
    ("prtAlertDescription", "alert text"),
    ("prtAlertTime", "time of the alert (sysUpTime)"),
    ("entityMIB", "model, serial number, firmware"),
    ("entPhysicalTable", "physical components of the device"),
    ("entPhysicalDescr", "description"),
    ("entPhysicalClass", "type: chassis, module, port..."),
    ("entPhysicalName", "name"),
    ("entPhysicalHardwareRev", "hardware revision"),
    ("entPhysicalFirmwareRev", "boot loader version"),
    ("entPhysicalSoftwareRev", "firmware version"),
    ("entPhysicalSerialNum", "serial number"),
    ("entPhysicalMfgName", "manufacturer"),
    ("entPhysicalModelName", "model"),
    ("lldpMIB", "LLDP neighbours"),
    ("lldpLocChassisId", "identifier of this device"),
    ("lldpLocSysName", "name advertised to neighbours"),
    ("lldpLocSysDesc", "description advertised to neighbours"),
    ("lldpLocPortTable", "local ports speaking LLDP"),
    ("lldpLocPortIdSubtype", "port identifier type"),
    ("lldpLocPortId", "port identifier"),
    ("lldpLocPortDesc", "port description"),
    ("lldpRemTable", "one neighbour per row"),
    ("lldpRemChassisIdSubtype", "neighbour identifier type"),
    ("lldpRemChassisId", "neighbour identifier"),
    ("lldpRemPortIdSubtype", "type of its port identifier"),
    ("lldpRemPortId", "neighbour port"),
    ("lldpRemPortDesc", "neighbour port description"),
    ("lldpRemSysName", "neighbour name"),
    ("lldpRemSysDesc", "neighbour description"),
    ("lldpRemSysCapSupported", "possible functions"),
    ("lldpRemSysCapEnabled", "active functions"),
    ("lldpRemManAddrTable", "neighbours' management addresses"),
    ("lldpRemManAddrIfSubtype", "management interface type"),
    ("lldpRemManAddrIfId", "management interface"),
];

const fn g(oid: &'static str, name: &'static str, mib: &'static str, descr: &'static str) -> Obj {
    Obj {
        oid,
        name,
        mib,
        kind: Kind::Group,
        descr,
    }
}
const fn s(oid: &'static str, name: &'static str, mib: &'static str, descr: &'static str) -> Obj {
    Obj {
        oid,
        name,
        mib,
        kind: Kind::Scalar,
        descr,
    }
}
const fn t(oid: &'static str, name: &'static str, mib: &'static str, descr: &'static str) -> Obj {
    Obj {
        oid,
        name,
        mib,
        kind: Kind::Table,
        descr,
    }
}
const fn c(oid: &'static str, name: &'static str, mib: &'static str, descr: &'static str) -> Obj {
    Obj {
        oid,
        name,
        mib,
        kind: Kind::Column,
        descr,
    }
}

const SYS: &str = "SNMPv2-MIB";
const IF: &str = "IF-MIB";
const IP: &str = "IP-MIB";
const BR: &str = "BRIDGE-MIB";
const QBR: &str = "Q-BRIDGE-MIB";
const HR: &str = "HOST-RESOURCES-MIB";
const PRT: &str = "Printer-MIB";
const ENT: &str = "ENTITY-MIB";
const LLDP: &str = "LLDP-MIB";

/// Objects of the standard MIBs, in OID order within each branch.
pub const OBJECTS: &[Obj] = &[
    g("1.3.6.1.2.1", "mib-2", "SNMPv2-SMI", "oggetti standard"),
    // ── system ──
    g("1.3.6.1.2.1.1", "system", SYS, "identità dell'apparato"),
    s(
        "1.3.6.1.2.1.1.1",
        "sysDescr",
        SYS,
        "descrizione: modello e firmware",
    ),
    s(
        "1.3.6.1.2.1.1.2",
        "sysObjectID",
        SYS,
        "identificativo del tipo di apparato",
    ),
    s(
        "1.3.6.1.2.1.1.3",
        "sysUpTime",
        SYS,
        "tempo dall'avvio dell'agente",
    ),
    s(
        "1.3.6.1.2.1.1.4",
        "sysContact",
        SYS,
        "persona di riferimento",
    ),
    s("1.3.6.1.2.1.1.5", "sysName", SYS, "nome dell'apparato"),
    s("1.3.6.1.2.1.1.6", "sysLocation", SYS, "posizione fisica"),
    s(
        "1.3.6.1.2.1.1.7",
        "sysServices",
        SYS,
        "livelli di rete serviti",
    ),
    // ── interfaces ──
    g("1.3.6.1.2.1.2", "interfaces", IF, "interfacce di rete"),
    s("1.3.6.1.2.1.2.1", "ifNumber", IF, "numero di interfacce"),
    t("1.3.6.1.2.1.2.2", "ifTable", IF, "una riga per interfaccia"),
    c(
        "1.3.6.1.2.1.2.2.1.1",
        "ifIndex",
        IF,
        "numero dell'interfaccia",
    ),
    c("1.3.6.1.2.1.2.2.1.2", "ifDescr", IF, "descrizione"),
    c("1.3.6.1.2.1.2.2.1.3", "ifType", IF, "tipo di interfaccia"),
    c(
        "1.3.6.1.2.1.2.2.1.4",
        "ifMtu",
        IF,
        "dimensione massima del pacchetto",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.5",
        "ifSpeed",
        IF,
        "velocità in bit/s (fino a 4 Gb/s)",
    ),
    c("1.3.6.1.2.1.2.2.1.6", "ifPhysAddress", IF, "indirizzo MAC"),
    c(
        "1.3.6.1.2.1.2.2.1.7",
        "ifAdminStatus",
        IF,
        "stato voluto dall'amministratore",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.8",
        "ifOperStatus",
        IF,
        "stato del collegamento",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.9",
        "ifLastChange",
        IF,
        "sysUpTime dell'ultimo cambio di stato",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.10",
        "ifInOctets",
        IF,
        "byte ricevuti (32 bit)",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.11",
        "ifInUcastPkts",
        IF,
        "pacchetti unicast ricevuti",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.13",
        "ifInDiscards",
        IF,
        "pacchetti ricevuti e scartati",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.14",
        "ifInErrors",
        IF,
        "pacchetti ricevuti con errori",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.15",
        "ifInUnknownProtos",
        IF,
        "pacchetti di protocolli sconosciuti",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.16",
        "ifOutOctets",
        IF,
        "byte inviati (32 bit)",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.17",
        "ifOutUcastPkts",
        IF,
        "pacchetti unicast inviati",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.19",
        "ifOutDiscards",
        IF,
        "pacchetti in uscita scartati",
    ),
    c(
        "1.3.6.1.2.1.2.2.1.20",
        "ifOutErrors",
        IF,
        "pacchetti non inviati per errori",
    ),
    // ── ip ──
    g("1.3.6.1.2.1.4", "ip", IP, "indirizzi e tabella ARP"),
    s(
        "1.3.6.1.2.1.4.1",
        "ipForwarding",
        IP,
        "l'apparato inoltra pacchetti (router)",
    ),
    s("1.3.6.1.2.1.4.2", "ipDefaultTTL", IP, "TTL predefinito"),
    t(
        "1.3.6.1.2.1.4.20",
        "ipAddrTable",
        IP,
        "indirizzi IPv4 dell'apparato",
    ),
    c("1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr", IP, "indirizzo"),
    c(
        "1.3.6.1.2.1.4.20.1.2",
        "ipAdEntIfIndex",
        IP,
        "interfaccia dell'indirizzo",
    ),
    c(
        "1.3.6.1.2.1.4.20.1.3",
        "ipAdEntNetMask",
        IP,
        "maschera di rete",
    ),
    c(
        "1.3.6.1.2.1.4.20.1.4",
        "ipAdEntBcastAddr",
        IP,
        "bit meno significativo del broadcast",
    ),
    t(
        "1.3.6.1.2.1.4.22",
        "ipNetToMediaTable",
        IP,
        "tabella ARP (IPv4)",
    ),
    c(
        "1.3.6.1.2.1.4.22.1.1",
        "ipNetToMediaIfIndex",
        IP,
        "interfaccia",
    ),
    c(
        "1.3.6.1.2.1.4.22.1.2",
        "ipNetToMediaPhysAddress",
        IP,
        "indirizzo MAC",
    ),
    c(
        "1.3.6.1.2.1.4.22.1.3",
        "ipNetToMediaNetAddress",
        IP,
        "indirizzo IP",
    ),
    c(
        "1.3.6.1.2.1.4.22.1.4",
        "ipNetToMediaType",
        IP,
        "dinamico o statico",
    ),
    t(
        "1.3.6.1.2.1.4.35",
        "ipNetToPhysicalTable",
        IP,
        "tabella dei vicini (IPv4 e IPv6)",
    ),
    c(
        "1.3.6.1.2.1.4.35.1.4",
        "ipNetToPhysicalPhysAddress",
        IP,
        "indirizzo MAC",
    ),
    c(
        "1.3.6.1.2.1.4.35.1.6",
        "ipNetToPhysicalType",
        IP,
        "dinamico o statico",
    ),
    c(
        "1.3.6.1.2.1.4.35.1.7",
        "ipNetToPhysicalState",
        IP,
        "stato della voce",
    ),
    // ── bridge ──
    g(
        "1.3.6.1.2.1.17",
        "dot1dBridge",
        BR,
        "switch: porte e tabella MAC",
    ),
    s(
        "1.3.6.1.2.1.17.1.1",
        "dot1dBaseBridgeAddress",
        BR,
        "indirizzo MAC dello switch",
    ),
    s(
        "1.3.6.1.2.1.17.1.2",
        "dot1dBaseNumPorts",
        BR,
        "numero di porte",
    ),
    t(
        "1.3.6.1.2.1.17.1.4",
        "dot1dBasePortTable",
        BR,
        "porte dello switch",
    ),
    c(
        "1.3.6.1.2.1.17.1.4.1.1",
        "dot1dBasePort",
        BR,
        "numero di porta dello switch",
    ),
    c(
        "1.3.6.1.2.1.17.1.4.1.2",
        "dot1dBasePortIfIndex",
        BR,
        "interfaccia della porta",
    ),
    t(
        "1.3.6.1.2.1.17.4.3",
        "dot1dTpFdbTable",
        BR,
        "tabella MAC (senza VLAN)",
    ),
    c(
        "1.3.6.1.2.1.17.4.3.1.1",
        "dot1dTpFdbAddress",
        BR,
        "indirizzo MAC",
    ),
    c(
        "1.3.6.1.2.1.17.4.3.1.2",
        "dot1dTpFdbPort",
        BR,
        "porta su cui è stato visto",
    ),
    c(
        "1.3.6.1.2.1.17.4.3.1.3",
        "dot1dTpFdbStatus",
        BR,
        "imparato o configurato",
    ),
    g("1.3.6.1.2.1.17.7", "qBridgeMIB", QBR, "switch con VLAN"),
    t(
        "1.3.6.1.2.1.17.7.1.2.2",
        "dot1qTpFdbTable",
        QBR,
        "tabella MAC per VLAN",
    ),
    c(
        "1.3.6.1.2.1.17.7.1.2.2.1.2",
        "dot1qTpFdbPort",
        QBR,
        "porta su cui è stato visto",
    ),
    c(
        "1.3.6.1.2.1.17.7.1.2.2.1.3",
        "dot1qTpFdbStatus",
        QBR,
        "imparato o configurato",
    ),
    t(
        "1.3.6.1.2.1.17.7.1.4.3",
        "dot1qVlanStaticTable",
        QBR,
        "VLAN configurate",
    ),
    c(
        "1.3.6.1.2.1.17.7.1.4.3.1.1",
        "dot1qVlanStaticName",
        QBR,
        "nome della VLAN",
    ),
    // ── host resources ──
    g("1.3.6.1.2.1.25", "host", HR, "memoria, dischi, CPU"),
    g(
        "1.3.6.1.2.1.25.1",
        "hrSystem",
        HR,
        "avvio, utenti e processi",
    ),
    s(
        "1.3.6.1.2.1.25.1.1",
        "hrSystemUptime",
        HR,
        "tempo dall'avvio del sistema",
    ),
    s(
        "1.3.6.1.2.1.25.1.2",
        "hrSystemDate",
        HR,
        "data e ora del sistema",
    ),
    s(
        "1.3.6.1.2.1.25.1.5",
        "hrSystemNumUsers",
        HR,
        "utenti collegati",
    ),
    s(
        "1.3.6.1.2.1.25.1.6",
        "hrSystemProcesses",
        HR,
        "processi in esecuzione",
    ),
    s(
        "1.3.6.1.2.1.25.2.2",
        "hrMemorySize",
        HR,
        "memoria fisica in KB",
    ),
    t(
        "1.3.6.1.2.1.25.2.3",
        "hrStorageTable",
        HR,
        "dischi e memoria",
    ),
    c("1.3.6.1.2.1.25.2.3.1.1", "hrStorageIndex", HR, "numero"),
    c(
        "1.3.6.1.2.1.25.2.3.1.2",
        "hrStorageType",
        HR,
        "tipo: RAM, disco, rete…",
    ),
    c(
        "1.3.6.1.2.1.25.2.3.1.3",
        "hrStorageDescr",
        HR,
        "descrizione o punto di montaggio",
    ),
    c(
        "1.3.6.1.2.1.25.2.3.1.4",
        "hrStorageAllocationUnits",
        HR,
        "byte per unità",
    ),
    c(
        "1.3.6.1.2.1.25.2.3.1.5",
        "hrStorageSize",
        HR,
        "dimensione in unità",
    ),
    c(
        "1.3.6.1.2.1.25.2.3.1.6",
        "hrStorageUsed",
        HR,
        "spazio usato in unità",
    ),
    c(
        "1.3.6.1.2.1.25.2.3.1.7",
        "hrStorageAllocationFailures",
        HR,
        "richieste di spazio rifiutate",
    ),
    t(
        "1.3.6.1.2.1.25.3.2",
        "hrDeviceTable",
        HR,
        "dispositivi del sistema",
    ),
    c(
        "1.3.6.1.2.1.25.3.2.1.2",
        "hrDeviceType",
        HR,
        "tipo di dispositivo",
    ),
    c(
        "1.3.6.1.2.1.25.3.2.1.3",
        "hrDeviceDescr",
        HR,
        "descrizione o modello",
    ),
    c("1.3.6.1.2.1.25.3.2.1.5", "hrDeviceStatus", HR, "stato"),
    c(
        "1.3.6.1.2.1.25.3.2.1.6",
        "hrDeviceErrors",
        HR,
        "errori rilevati dal dispositivo",
    ),
    t("1.3.6.1.2.1.25.3.3", "hrProcessorTable", HR, "processori"),
    c(
        "1.3.6.1.2.1.25.3.3.1.2",
        "hrProcessorLoad",
        HR,
        "carico medio dell'ultimo minuto (%)",
    ),
    t(
        "1.3.6.1.2.1.25.3.5",
        "hrPrinterTable",
        HR,
        "stato delle stampanti del sistema",
    ),
    c(
        "1.3.6.1.2.1.25.3.5.1.1",
        "hrPrinterStatus",
        HR,
        "stato della stampante",
    ),
    c(
        "1.3.6.1.2.1.25.3.5.1.2",
        "hrPrinterDetectedErrorState",
        HR,
        "errori rilevati (carta, toner, sportello)",
    ),
    t(
        "1.3.6.1.2.1.25.4.2",
        "hrSWRunTable",
        HR,
        "processi in esecuzione",
    ),
    c(
        "1.3.6.1.2.1.25.4.2.1.2",
        "hrSWRunName",
        HR,
        "nome del processo",
    ),
    c(
        "1.3.6.1.2.1.25.4.2.1.4",
        "hrSWRunPath",
        HR,
        "percorso del programma",
    ),
    c(
        "1.3.6.1.2.1.25.4.2.1.5",
        "hrSWRunParameters",
        HR,
        "parametri di avvio",
    ),
    c(
        "1.3.6.1.2.1.25.4.2.1.6",
        "hrSWRunType",
        HR,
        "tipo: sistema, driver, applicazione",
    ),
    c(
        "1.3.6.1.2.1.25.4.2.1.7",
        "hrSWRunStatus",
        HR,
        "stato del processo",
    ),
    t(
        "1.3.6.1.2.1.25.5.1",
        "hrSWRunPerfTable",
        HR,
        "risorse usate dai processi",
    ),
    c(
        "1.3.6.1.2.1.25.5.1.1.1",
        "hrSWRunPerfCPU",
        HR,
        "tempo di CPU in centesimi di secondo",
    ),
    c(
        "1.3.6.1.2.1.25.5.1.1.2",
        "hrSWRunPerfMem",
        HR,
        "memoria usata in KB",
    ),
    // ── ifMIB ──
    g(
        "1.3.6.1.2.1.31",
        "ifMIB",
        IF,
        "nomi, alias e contatori a 64 bit",
    ),
    t(
        "1.3.6.1.2.1.31.1.1",
        "ifXTable",
        IF,
        "estensione della tabella delle interfacce",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.1",
        "ifName",
        IF,
        "nome breve dell'interfaccia",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.2",
        "ifInMulticastPkts",
        IF,
        "pacchetti multicast ricevuti",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.3",
        "ifInBroadcastPkts",
        IF,
        "pacchetti broadcast ricevuti",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.4",
        "ifOutMulticastPkts",
        IF,
        "pacchetti multicast inviati",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.5",
        "ifOutBroadcastPkts",
        IF,
        "pacchetti broadcast inviati",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.6",
        "ifHCInOctets",
        IF,
        "byte ricevuti, contatore a 64 bit",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.10",
        "ifHCOutOctets",
        IF,
        "byte inviati, contatore a 64 bit",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.15",
        "ifHighSpeed",
        IF,
        "velocità in Mb/s",
    ),
    c(
        "1.3.6.1.2.1.31.1.1.1.18",
        "ifAlias",
        IF,
        "descrizione scritta dall'amministratore",
    ),
    // ── stampanti ──
    g(
        "1.3.6.1.2.1.43",
        "printmib",
        PRT,
        "stampanti: vassoi e materiali",
    ),
    t(
        "1.3.6.1.2.1.43.5.1",
        "prtGeneralTable",
        PRT,
        "dati generali della stampante",
    ),
    c(
        "1.3.6.1.2.1.43.5.1.1.16",
        "prtGeneralPrinterName",
        PRT,
        "nome della stampante",
    ),
    c(
        "1.3.6.1.2.1.43.5.1.1.17",
        "prtGeneralSerialNumber",
        PRT,
        "numero di serie",
    ),
    c(
        "1.3.6.1.2.1.43.5.1.1.18",
        "prtAlertCriticalEvents",
        PRT,
        "allarmi critici dall'avvio",
    ),
    c(
        "1.3.6.1.2.1.43.5.1.1.19",
        "prtAlertAllEvents",
        PRT,
        "tutti gli allarmi dall'avvio",
    ),
    t(
        "1.3.6.1.2.1.43.8.2",
        "prtInputTable",
        PRT,
        "vassoi della carta",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.2",
        "prtInputType",
        PRT,
        "tipo di vassoio",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.8",
        "prtInputCapacityUnit",
        PRT,
        "unità di capienza e livello",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.9",
        "prtInputMaxCapacity",
        PRT,
        "capienza del vassoio",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.10",
        "prtInputCurrentLevel",
        PRT,
        "fogli presenti",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.12",
        "prtInputMediaName",
        PRT,
        "formato della carta",
    ),
    c(
        "1.3.6.1.2.1.43.8.2.1.13",
        "prtInputName",
        PRT,
        "nome del vassoio",
    ),
    t(
        "1.3.6.1.2.1.43.10.2",
        "prtMarkerTable",
        PRT,
        "unità di stampa",
    ),
    c(
        "1.3.6.1.2.1.43.10.2.1.2",
        "prtMarkerMarkTech",
        PRT,
        "tecnologia di stampa",
    ),
    c(
        "1.3.6.1.2.1.43.10.2.1.3",
        "prtMarkerCounterUnit",
        PRT,
        "unità dei contatori",
    ),
    c(
        "1.3.6.1.2.1.43.10.2.1.4",
        "prtMarkerLifeCount",
        PRT,
        "pagine stampate in totale",
    ),
    c(
        "1.3.6.1.2.1.43.10.2.1.5",
        "prtMarkerPowerOnCount",
        PRT,
        "pagine dall'ultima accensione",
    ),
    t(
        "1.3.6.1.2.1.43.11.1",
        "prtMarkerSuppliesTable",
        PRT,
        "toner e materiali di consumo",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.2",
        "prtMarkerSuppliesMarkerIndex",
        PRT,
        "unità di stampa servita",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.3",
        "prtMarkerSuppliesColorantIndex",
        PRT,
        "colorante (0 = nessuno)",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.4",
        "prtMarkerSuppliesClass",
        PRT,
        "si consuma o si riempie",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.5",
        "prtMarkerSuppliesType",
        PRT,
        "tipo di materiale",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.6",
        "prtMarkerSuppliesDescription",
        PRT,
        "descrizione del materiale",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.7",
        "prtMarkerSuppliesSupplyUnit",
        PRT,
        "unità di misura",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.8",
        "prtMarkerSuppliesMaxCapacity",
        PRT,
        "capienza",
    ),
    c(
        "1.3.6.1.2.1.43.11.1.1.9",
        "prtMarkerSuppliesLevel",
        PRT,
        "livello attuale",
    ),
    t(
        "1.3.6.1.2.1.43.12.1",
        "prtMarkerColorantTable",
        PRT,
        "coloranti",
    ),
    c(
        "1.3.6.1.2.1.43.12.1.1.3",
        "prtMarkerColorantRole",
        PRT,
        "ruolo del colorante",
    ),
    c(
        "1.3.6.1.2.1.43.12.1.1.4",
        "prtMarkerColorantValue",
        PRT,
        "nome del colore",
    ),
    t(
        "1.3.6.1.2.1.43.18.1",
        "prtAlertTable",
        PRT,
        "avvisi della stampante",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.2",
        "prtAlertSeverityLevel",
        PRT,
        "gravità dell'avviso",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.3",
        "prtAlertTrainingLevel",
        PRT,
        "chi deve intervenire",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.4",
        "prtAlertGroup",
        PRT,
        "parte della stampante interessata",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.5",
        "prtAlertGroupIndex",
        PRT,
        "numero della parte interessata",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.7",
        "prtAlertCode",
        PRT,
        "codice dell'avviso",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.8",
        "prtAlertDescription",
        PRT,
        "testo dell'avviso",
    ),
    c(
        "1.3.6.1.2.1.43.18.1.1.9",
        "prtAlertTime",
        PRT,
        "momento dell'avviso (sysUpTime)",
    ),
    // ── entity ──
    g(
        "1.3.6.1.2.1.47",
        "entityMIB",
        ENT,
        "modello, seriale, firmware",
    ),
    t(
        "1.3.6.1.2.1.47.1.1.1",
        "entPhysicalTable",
        ENT,
        "componenti fisici dell'apparato",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.2",
        "entPhysicalDescr",
        ENT,
        "descrizione",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.5",
        "entPhysicalClass",
        ENT,
        "tipo: chassis, modulo, porta…",
    ),
    c("1.3.6.1.2.1.47.1.1.1.1.7", "entPhysicalName", ENT, "nome"),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.8",
        "entPhysicalHardwareRev",
        ENT,
        "revisione hardware",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.9",
        "entPhysicalFirmwareRev",
        ENT,
        "versione del boot loader",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.10",
        "entPhysicalSoftwareRev",
        ENT,
        "versione del firmware",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.11",
        "entPhysicalSerialNum",
        ENT,
        "numero di serie",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.12",
        "entPhysicalMfgName",
        ENT,
        "costruttore",
    ),
    c(
        "1.3.6.1.2.1.47.1.1.1.1.13",
        "entPhysicalModelName",
        ENT,
        "modello",
    ),
    // ── LLDP ──
    g("1.0.8802.1.1.2", "lldpMIB", LLDP, "vicini LLDP"),
    s(
        "1.0.8802.1.1.2.1.3.2",
        "lldpLocChassisId",
        LLDP,
        "identificativo di questo apparato",
    ),
    s(
        "1.0.8802.1.1.2.1.3.3",
        "lldpLocSysName",
        LLDP,
        "nome annunciato ai vicini",
    ),
    s(
        "1.0.8802.1.1.2.1.3.4",
        "lldpLocSysDesc",
        LLDP,
        "descrizione annunciata ai vicini",
    ),
    t(
        "1.0.8802.1.1.2.1.3.7",
        "lldpLocPortTable",
        LLDP,
        "porte locali che parlano LLDP",
    ),
    c(
        "1.0.8802.1.1.2.1.3.7.1.2",
        "lldpLocPortIdSubtype",
        LLDP,
        "tipo di identificativo della porta",
    ),
    c(
        "1.0.8802.1.1.2.1.3.7.1.3",
        "lldpLocPortId",
        LLDP,
        "identificativo della porta",
    ),
    c(
        "1.0.8802.1.1.2.1.3.7.1.4",
        "lldpLocPortDesc",
        LLDP,
        "descrizione della porta",
    ),
    t(
        "1.0.8802.1.1.2.1.4.1",
        "lldpRemTable",
        LLDP,
        "un vicino per riga",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.4",
        "lldpRemChassisIdSubtype",
        LLDP,
        "tipo di identificativo del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.5",
        "lldpRemChassisId",
        LLDP,
        "identificativo del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.6",
        "lldpRemPortIdSubtype",
        LLDP,
        "tipo di identificativo della sua porta",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.7",
        "lldpRemPortId",
        LLDP,
        "porta del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.8",
        "lldpRemPortDesc",
        LLDP,
        "descrizione della porta del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.9",
        "lldpRemSysName",
        LLDP,
        "nome del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.10",
        "lldpRemSysDesc",
        LLDP,
        "descrizione del vicino",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.11",
        "lldpRemSysCapSupported",
        LLDP,
        "funzioni possibili",
    ),
    c(
        "1.0.8802.1.1.2.1.4.1.1.12",
        "lldpRemSysCapEnabled",
        LLDP,
        "funzioni attive",
    ),
    t(
        "1.0.8802.1.1.2.1.4.2",
        "lldpRemManAddrTable",
        LLDP,
        "indirizzi di gestione dei vicini",
    ),
    c(
        "1.0.8802.1.1.2.1.4.2.1.3",
        "lldpRemManAddrIfSubtype",
        LLDP,
        "tipo di interfaccia di gestione",
    ),
    c(
        "1.0.8802.1.1.2.1.4.2.1.4",
        "lldpRemManAddrIfId",
        LLDP,
        "interfaccia di gestione",
    ),
];

/// OID-type values with a name (they do not appear in the tree).
const IDENTITIES: &[(&str, &str)] = &[
    ("1.3.6.1.2.1.25.2.1.1", "hrStorageOther"),
    ("1.3.6.1.2.1.25.2.1.2", "hrStorageRam"),
    ("1.3.6.1.2.1.25.2.1.3", "hrStorageVirtualMemory"),
    ("1.3.6.1.2.1.25.2.1.4", "hrStorageFixedDisk"),
    ("1.3.6.1.2.1.25.2.1.5", "hrStorageRemovableDisk"),
    ("1.3.6.1.2.1.25.2.1.7", "hrStorageCompactDisc"),
    ("1.3.6.1.2.1.25.2.1.8", "hrStorageRamDisk"),
    ("1.3.6.1.2.1.25.2.1.9", "hrStorageFlashMemory"),
    ("1.3.6.1.2.1.25.2.1.10", "hrStorageNetworkDisk"),
    ("1.3.6.1.2.1.25.3.1.3", "hrDeviceProcessor"),
    ("1.3.6.1.2.1.25.3.1.4", "hrDeviceNetwork"),
    ("1.3.6.1.2.1.25.3.1.5", "hrDevicePrinter"),
    ("1.3.6.1.2.1.25.3.1.6", "hrDeviceDiskStorage"),
    ("0.0", "zeroDotZero"),
];

pub fn arcs(s: &str) -> Option<Vec<u32>> {
    let v: Option<Vec<u32>> = s
        .trim()
        .trim_start_matches('.')
        .split('.')
        .map(|x| x.parse().ok())
        .collect();
    v.filter(|v| v.len() >= 2)
}

pub fn dotted(o: &[u32]) -> String {
    o.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Objects with the OID already split, computed once.
fn index() -> &'static [(Vec<u32>, &'static Obj)] {
    static INDEX: OnceLock<Vec<(Vec<u32>, &'static Obj)>> = OnceLock::new();
    INDEX.get_or_init(|| {
        OBJECTS
            .iter()
            .filter_map(|o| arcs(o.oid).map(|a| (a, o)))
            .collect()
    })
}

/// Object with this name (case-insensitive).
pub fn find(name: &str) -> Option<&'static Obj> {
    OBJECTS.iter().find(|o| o.name.eq_ignore_ascii_case(name))
}

/// OID of a built-in name. For constants in the code: the name must exist.
pub fn oid_of(name: &str) -> Vec<u32> {
    find(name)
        .and_then(|o| arcs(o.oid))
        .unwrap_or_else(|| panic!("nome SNMP non integrato: {name}"))
}

/// The most specific object containing `o` and the length of its OID.
pub fn object(o: &[u32]) -> Option<(&'static Obj, usize)> {
    index()
        .iter()
        .filter(|(a, _)| o.starts_with(a))
        .max_by_key(|(a, _)| a.len())
        .map(|(a, obj)| (*obj, a.len()))
}

/// OID from text: numeric (1.3.6.1...) or by name (sysDescr.0, ifTable, IF-MIB::ifDescr).
pub fn parse_oid(input: &str) -> Option<Vec<u32>> {
    let s = input.trim();
    if let Some(v) = arcs(s) {
        return Some(v);
    }
    let s = s.rsplit("::").next().unwrap_or(s);
    let (name, rest) = s
        .split_once('.')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((s, None));
    let mut v = arcs(find(name)?.oid)?;
    if let Some(r) = rest {
        v.extend(arcs(&format!("0.{r}"))?.into_iter().skip(1));
    }
    Some(v)
}

/// Symbolic name: SNMPv2-MIB::sysDescr.0, or the numeric OID.
pub fn name(o: &[u32]) -> String {
    match object(o) {
        // a group names only itself: below it, the full OID is better
        Some((obj, len)) if len == o.len() => format!("{}::{}", obj.mib, obj.name),
        Some((obj, len)) if obj.kind != Kind::Group => {
            format!("{}::{}.{}", obj.mib, obj.name, dotted(&o[len..]))
        }
        _ => format!(".{}", dotted(o)),
    }
}

/// Name without the MIB (`ifDescr.3`), for table headers.
pub fn short_name(o: &[u32]) -> String {
    let n = name(o);
    match n.split_once("::") {
        Some((_, s)) => s.to_string(),
        None => n.trim_start_matches('.').to_string(),
    }
}

fn identity(o: &[u32]) -> Option<&'static str> {
    let d = dotted(o);
    IDENTITIES.iter().find(|(oid, _)| *oid == d).map(|x| x.1)
}

pub fn if_status(v: i64) -> Option<&'static str> {
    Some(match v {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notPresent",
        7 => "lowerLayerDown",
        _ => return None,
    })
}

pub fn if_type(v: i64) -> Option<&'static str> {
    Some(match v {
        1 => "other",
        6 => "ethernetCsmacd",
        23 => "ppp",
        24 => "softwareLoopback",
        53 => "propVirtual",
        71 => "ieee80211",
        131 => "tunnel",
        135 => "l2vlan",
        136 => "l3ipvlan",
        161 => "ieee8023adLag",
        _ => return None,
    })
}

/// Label of an enumerated integer value, from the object's name.
pub fn enum_label(object: &str, v: i64) -> Option<&'static str> {
    match object {
        "ifAdminStatus" | "ifOperStatus" => if_status(v),
        "ifType" => if_type(v),
        "ipNetToMediaType" | "ipNetToPhysicalType" => Some(match v {
            1 => "other",
            2 => "invalid",
            3 => "dynamic",
            4 => "static",
            5 => "local",
            _ => return None,
        }),
        "dot1dTpFdbStatus" | "dot1qTpFdbStatus" => Some(match v {
            1 => "other",
            2 => "invalid",
            3 => "learned",
            4 => "self",
            5 => "mgmt",
            _ => return None,
        }),
        "ipForwarding" => Some(match v {
            1 => "forwarding",
            2 => "notForwarding",
            _ => return None,
        }),
        "entPhysicalClass" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "chassis",
            4 => "backplane",
            5 => "container",
            6 => "powerSupply",
            7 => "fan",
            8 => "sensor",
            9 => "module",
            10 => "port",
            11 => "stack",
            _ => return None,
        }),
        "hrPrinterStatus" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "idle",
            4 => "printing",
            5 => "warmup",
            _ => return None,
        }),
        "hrSWRunType" => Some(match v {
            1 => "unknown",
            2 => "operatingSystem",
            3 => "deviceDriver",
            4 => "application",
            _ => return None,
        }),
        "hrSWRunStatus" => Some(match v {
            1 => "running",
            2 => "runnable",
            3 => "notRunnable",
            4 => "invalid",
            _ => return None,
        }),
        "prtMarkerSuppliesLevel"
        | "prtMarkerSuppliesMaxCapacity"
        | "prtInputCurrentLevel"
        | "prtInputMaxCapacity" => Some(match v {
            -1 => "other",
            -2 => "unknown",
            -3 => "somethingRemains",
            _ => return None,
        }),
        "prtMarkerSuppliesClass" => Some(match v {
            1 => "other",
            3 => "supplyThatIsConsumed",
            4 => "receptacleThatIsFilled",
            _ => return None,
        }),
        "prtMarkerSuppliesType" => supply_type(v),
        "prtMarkerSuppliesSupplyUnit" | "prtInputCapacityUnit" | "prtMarkerCounterUnit" => unit(v),
        "prtInputType" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "sheetFeedAutoRemovableTray",
            4 => "sheetFeedAutoNonRemovableTray",
            5 => "sheetFeedManual",
            6 => "continuousRoll",
            7 => "continuousFanFold",
            _ => return None,
        }),
        "prtMarkerMarkTech" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "electrophotographicLED",
            4 => "electrophotographicLaser",
            5 => "electrophotographicOther",
            _ => return None,
        }),
        "prtMarkerColorantRole" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "highlight",
            4 => "process",
            5 => "spot",
            _ => return None,
        }),
        "prtAlertSeverityLevel" => Some(match v {
            1 => "other",
            3 => "critical",
            4 => "warning",
            5 => "warningBinaryChangeEvent",
            _ => return None,
        }),
        "prtAlertTrainingLevel" => Some(match v {
            1 => "other",
            2 => "unknown",
            3 => "untrained",
            4 => "trained",
            5 => "fieldService",
            6 => "management",
            7 => "noInterventionRequired",
            _ => return None,
        }),
        "prtAlertGroup" => alert_group(v),
        "prtAlertCode" => alert_code(v),
        "hrDeviceStatus" => Some(match v {
            1 => "unknown",
            2 => "running",
            3 => "warning",
            4 => "testing",
            5 => "down",
            _ => return None,
        }),
        _ => None,
    }
}

/// Tipi di materiale (Printer-MIB, PrtMarkerSuppliesTypeTC).
pub fn supply_type(v: i64) -> Option<&'static str> {
    const T: [&str; 34] = [
        "other",
        "unknown",
        "toner",
        "wasteToner",
        "ink",
        "inkCartridge",
        "inkRibbon",
        "wasteInk",
        "opc",
        "developer",
        "fuserOil",
        "solidWax",
        "ribbonWax",
        "wasteWax",
        "fuser",
        "coronaWire",
        "fuserOilWick",
        "cleanerUnit",
        "fuserCleaningPad",
        "transferUnit",
        "tonerCartridge",
        "fuserOiler",
        "water",
        "wasteWater",
        "glueWaterAdditive",
        "wastePaper",
        "bindingSupply",
        "bandingSupply",
        "stitchingWire",
        "shrinkWrap",
        "paperWrap",
        "staples",
        "inserts",
        "covers",
    ];
    usize::try_from(v - 1).ok().and_then(|i| T.get(i).copied())
}

/// Units of measure (Printer-MIB): supplies, trays and counters.
pub fn unit(v: i64) -> Option<&'static str> {
    Some(match v {
        1 => "other",
        2 => "unknown",
        3 => "tenThousandthsOfInches",
        4 => "micrometers",
        5 => "characters",
        6 => "lines",
        7 => "impressions",
        8 => "sheets",
        9 => "dotRow",
        11 => "hours",
        12 => "thousandthsOfOunces",
        13 => "tenthsOfGrams",
        14 => "hundredthsOfFluidOunces",
        15 => "tenthsOfMilliliters",
        16 => "feet",
        17 => "meters",
        18 => "items",
        19 => "percent",
        _ => return None,
    })
}

fn alert_group(v: i64) -> Option<&'static str> {
    Some(match v {
        1 => "other",
        3 => "hostResourcesMIBStorageTable",
        4 => "hostResourcesMIBDeviceTable",
        5 => "generalPrinter",
        6 => "cover",
        7 => "localization",
        8 => "input",
        9 => "output",
        10 => "marker",
        11 => "markerSupplies",
        12 => "markerColorant",
        13 => "mediaPath",
        14 => "channel",
        15 => "interpreter",
        16 => "consoleDisplayBuffer",
        17 => "consoleLights",
        _ => return None,
    })
}

fn alert_code(v: i64) -> Option<&'static str> {
    const T: [&str; 38] = [
        "other",
        "unknown",
        "coverOpen",
        "coverClosed",
        "interlockOpen",
        "interlockClosed",
        "configurationChange",
        "jam",
        "subunitMissing",
        "subunitLifeAlmostOver",
        "subunitLifeOver",
        "subunitAlmostEmpty",
        "subunitEmpty",
        "subunitAlmostFull",
        "subunitFull",
        "subunitNearLimit",
        "subunitAtLimit",
        "subunitOpened",
        "subunitClosed",
        "subunitTurnedOn",
        "subunitTurnedOff",
        "subunitOffline",
        "subunitPowerSaver",
        "subunitWarmingUp",
        "subunitAdded",
        "subunitRemoved",
        "subunitResourceAdded",
        "subunitResourceRemoved",
        "subunitRecoverableFailure",
        "subunitUnrecoverableFailure",
        "subunitRecoverableStorageError",
        "subunitUnrecoverableStorageError",
        "subunitMotorFailure",
        "subunitMemoryExhausted",
        "subunitUnderTemperature",
        "subunitOverTemperature",
        "subunitTimingFailure",
        "subunitThermistorFailure",
    ];
    match v {
        1..=38 => T.get((v - 1) as usize).copied(),
        501 => Some("powerUp"),
        502 => Some("powerDown"),
        503 => Some("printerNMSReset"),
        504 => Some("printerManualReset"),
        505 => Some("printerReadyToPrint"),
        801 => Some("inputMediaTrayMissing"),
        807 => Some("inputMediaSupplyLow"),
        808 => Some("inputMediaSupplyEmpty"),
        1101 => Some("markerTonerEmpty"),
        1102 => Some("markerInkEmpty"),
        1104 => Some("markerTonerAlmostEmpty"),
        1105 => Some("markerInkAlmostEmpty"),
        1107 => Some("markerWasteTonerReceptacleAlmostFull"),
        1109 => Some("markerWasteTonerReceptacleFull"),
        1111 => Some("markerOpcLifeAlmostOver"),
        1112 => Some("markerOpcLifeOver"),
        1115 => Some("markerTonerCartridgeMissing"),
        _ => None,
    }
}

/// Objects whose value is a MAC address.
fn is_mac_object(object: &str) -> bool {
    matches!(
        object,
        "ifPhysAddress"
            | "ipNetToMediaPhysAddress"
            | "ipNetToPhysicalPhysAddress"
            | "dot1dTpFdbAddress"
            | "dot1dBaseBridgeAddress"
    )
}

pub fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// TimeTicks time without the raw value: "1 day, 1:01:01.05".
fn ticks_text(t: u64) -> String {
    let cs = t % 100;
    let s = t / 100;
    let (d, h, m, sec) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    let days = match d {
        0 => String::new(),
        1 => "1 day, ".into(),
        n => format!("{n} days, "),
    };
    format!("{days}{h}:{m:02}:{sec:02}.{cs:02}")
}

pub fn timeticks(t: u64) -> String {
    format!("({t}) {}", ticks_text(t))
}

/// Text of an SNMP string if printable (without trailing NULs).
pub fn printable(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    let trimmed = s.trim_end_matches('\0');
    trimmed
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\r' | '\n' | '\t'))
        .then(|| trimmed.to_string())
}

pub fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Value in Net-SNMP format ("INTEGER: up(1)", "STRING: \"…\"").
pub fn value(oid: &[u32], v: &Value) -> String {
    let obj = object(oid).map(|(o, _)| o.name).unwrap_or("");
    match v {
        Value::Int(i) => match enum_label(obj, *i) {
            Some(s) => format!("INTEGER: {s}({i})"),
            None => format!("INTEGER: {i}"),
        },
        Value::Str(b) if b.len() == 6 && is_mac_object(obj) => format!("STRING: {}", mac(b)),
        Value::Str(b) => match printable(b) {
            Some(s) => format!("STRING: \"{s}\""),
            None => format!("Hex-STRING: {}", hex(b)),
        },
        Value::Null => "NULL".into(),
        Value::Oid(o) => format!("OID: {}", name(o)),
        Value::Ip(a) => format!("IpAddress: {}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        Value::Counter32(c) => format!("Counter32: {c}"),
        Value::Gauge32(g) => format!("Gauge32: {g}"),
        Value::TimeTicks(t) => format!("Timeticks: {}", timeticks(*t)),
        Value::Opaque(b) => format!("Opaque: {}", hex(b)),
        Value::Counter64(c) => format!("Counter64: {c}"),
        Value::NoSuchObject => "No Such Object available on this agent at this OID".into(),
        Value::NoSuchInstance => "No Such Instance currently exists at this OID".into(),
        Value::EndOfMibView => {
            "No more variables left in this MIB View (It is past the end of the MIB tree)".into()
        }
        Value::Other(t, b) => crate::tf!("Tipo 0x{t:02x}: {}", "Type 0x{t:02x}: {}", hex(b)),
    }
}

/// Value for a table cell: only the content, without the type.
pub fn cell(oid: &[u32], v: &Value) -> String {
    let obj = object(oid).map(|(o, _)| o.name).unwrap_or("");
    match v {
        Value::Int(i) => match enum_label(obj, *i) {
            Some(s) => s.to_string(),
            None => i.to_string(),
        },
        Value::Str(b) if b.len() == 6 && is_mac_object(obj) => mac(b),
        Value::Str(b) => match printable(b) {
            Some(s) => s.split_whitespace().collect::<Vec<_>>().join(" "),
            None => hex(b),
        },
        Value::Null => String::new(),
        Value::Oid(o) => identity(o)
            .map(str::to_string)
            .unwrap_or_else(|| short_name(o)),
        Value::Ip(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        Value::Counter32(n) | Value::Gauge32(n) | Value::Counter64(n) => n.to_string(),
        Value::TimeTicks(t) => ticks_text(*t),
        Value::Opaque(b) => hex(b),
        Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => String::new(),
        Value::Other(_, b) => hex(b),
    }
}

pub fn line(oid: &[u32], v: &Value) -> String {
    format!("{} = {}", name(oid), value(oid, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nomi_e_valori() {
        assert_eq!(
            parse_oid("1.3.6.1.2.1.1.1.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 1, 1, 0]
        );
        assert_eq!(parse_oid(".1.3.6.1").unwrap(), vec![1, 3, 6, 1]);
        assert_eq!(
            parse_oid("sysDescr.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 1, 1, 0]
        );
        assert_eq!(
            parse_oid("SNMPv2-MIB::sysName.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 1, 5, 0]
        );
        assert_eq!(
            parse_oid("IF-MIB::ifDescr").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2]
        );
        assert_eq!(parse_oid("iftable").unwrap(), vec![1, 3, 6, 1, 2, 1, 2, 2]);
        assert_eq!(
            parse_oid("lldpRemTable").unwrap(),
            vec![1, 0, 8802, 1, 1, 2, 1, 4, 1]
        );
        assert!(parse_oid("1.3.6;id").is_none() && parse_oid("nonesiste").is_none());
        assert_eq!(name(&[1, 3, 6, 1, 2, 1, 1, 1, 0]), "SNMPv2-MIB::sysDescr.0");
        assert_eq!(
            name(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 7]),
            "IF-MIB::ifDescr.7"
        );
        assert_eq!(name(&[1, 3, 6, 1, 2, 1, 2, 2]), "IF-MIB::ifTable");
        // under a group without a more precise name the OID stays
        assert_eq!(
            name(&[1, 3, 6, 1, 2, 1, 1, 9, 1, 2, 1]),
            ".1.3.6.1.2.1.1.9.1.2.1"
        );
        assert_eq!(name(&[1, 3, 6, 1, 4, 1, 9]), ".1.3.6.1.4.1.9");
        assert_eq!(short_name(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2]), "ifDescr");
        assert_eq!(short_name(&[1, 3, 6, 1, 4, 1, 9]), "1.3.6.1.4.1.9");
        assert_eq!(timeticks(159), "(159) 0:00:01.59");
        assert_eq!(
            timeticks(8_640_000 + 360_000 + 6_000 + 100 + 5),
            "(9006105) 1 day, 1:01:01.05"
        );
        assert_eq!(
            line(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1], &Value::Int(2)),
            "IF-MIB::ifOperStatus.1 = INTEGER: down(2)"
        );
        assert_eq!(
            value(&[1, 3, 6, 1, 2, 1, 1, 5, 0], &Value::Str(b"fw01".to_vec())),
            "STRING: \"fw01\""
        );
        assert_eq!(
            value(
                &[1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1],
                &Value::Str(vec![0, 0x50, 0x56, 1, 2, 3])
            ),
            "STRING: 00:50:56:01:02:03"
        );
        assert_eq!(
            value(&[1, 3], &Value::Str(vec![0xff, 0x00, 0x10])),
            "Hex-STRING: FF 00 10"
        );
    }

    #[test]
    fn celle() {
        let o = |n: &str, i: u32| {
            let mut v = oid_of(n);
            v.push(i);
            v
        };
        assert_eq!(cell(&o("ifOperStatus", 3), &Value::Int(1)), "up");
        assert_eq!(cell(&o("ifType", 3), &Value::Int(6)), "ethernetCsmacd");
        assert_eq!(cell(&o("ifType", 3), &Value::Int(250)), "250");
        assert_eq!(cell(&o("ifMtu", 3), &Value::Int(1500)), "1500");
        assert_eq!(
            cell(
                &o("ifPhysAddress", 3),
                &Value::Str(vec![2, 0, 0x5e, 1, 2, 3])
            ),
            "02:00:5e:01:02:03"
        );
        assert_eq!(
            cell(&o("ifDescr", 3), &Value::Str(b"porta  1\r\n".to_vec())),
            "porta 1"
        );
        assert_eq!(
            cell(
                &o("hrStorageType", 1),
                &Value::Oid(vec![1, 3, 6, 1, 2, 1, 25, 2, 1, 4])
            ),
            "hrStorageFixedDisk"
        );
        assert_eq!(
            cell(&o("ifHCInOctets", 1), &Value::Counter64(1 << 40)),
            "1099511627776"
        );
        assert_eq!(
            cell(&o("ifLastChange", 1), &Value::TimeTicks(159)),
            "0:00:01.59"
        );
        assert_eq!(cell(&[1, 3], &Value::Ip([192, 0, 2, 1])), "192.0.2.1");
        assert_eq!(cell(&[1, 3], &Value::NoSuchInstance), "");
    }

    /// The names table is consistent: valid OIDs, no duplicates, every column inside a
    /// table, standard MIBs only (no `enterprises` branches).
    #[test]
    fn tabella_dei_nomi() {
        let mut names = std::collections::HashSet::new();
        let mut oids = std::collections::HashSet::new();
        for o in OBJECTS {
            let a = arcs(o.oid).unwrap_or_else(|| panic!("OID non valido: {}", o.oid));
            assert!(
                names.insert(o.name.to_lowercase()),
                "nome doppio: {}",
                o.name
            );
            assert!(oids.insert(o.oid), "OID doppio: {}", o.oid);
            assert!(
                !a.starts_with(&[1, 3, 6, 1, 4, 1]),
                "MIB privata: {}",
                o.name
            );
            assert!(!o.descr.is_empty(), "{} senza descrizione", o.name);
            assert!(
                descr_en(o.name).is_some(),
                "{}: missing English description",
                o.name
            );
            if o.kind == Kind::Column {
                let table = &a[..a.len() - 2];
                let parent = index().iter().find(|(x, _)| x.as_slice() == table);
                assert!(
                    matches!(parent, Some((_, p)) if p.kind == Kind::Table),
                    "{} non sta in una tabella",
                    o.name
                );
                assert_eq!(a[a.len() - 2], 1, "{}: colonna fuori dalla riga", o.name);
            }
        }
        assert!(OBJECTS.len() > 120);
    }

    /// With English selected, the names table serialises the English description.
    #[test]
    fn descrizioni_in_inglese() {
        let sys = find("sysDescr").unwrap();
        assert_eq!(sys.description(), "descrizione: modello e firmware");
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        assert_eq!(sys.description(), "description: model and firmware");
        let j = serde_json::to_value(sys).unwrap();
        assert_eq!(j["descr"], "description: model and firmware");
        assert_eq!(j["kind"], "scalar");
        assert_eq!(j["name"], "sysDescr");
        for o in OBJECTS {
            assert!(
                !o.description().contains(" dell")
                    && !o.description().contains(" della")
                    && !o.description().contains(" di "),
                "{}: {}",
                o.name,
                o.description()
            );
        }
        assert_eq!(
            value(&[1, 3], &Value::Other(0x99, vec![1])),
            "Type 0x99: 01"
        );
    }
}
