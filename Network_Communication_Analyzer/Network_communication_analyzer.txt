from scapy.all import *
vysielajuceIp = {}
counter = 1
bolean = 1
bolean2 = 1
boolean3 = 1
porty = 0
porty2 = 0
icmpPocet = 0
icmpCounter = 0
poleArp = []
requesty = {}
reply = {}
countArp = 1

#funkcia, ktora precita externe subory a ulozi do jednotlivych Types key-value -> na dany key (cislo) ulozi val (nazov)
def nacitajSubory(nazovSuboru):
    vysledok = {}
    subory = open(nazovSuboru, "r")
    for subor in subory:
        (key, val) = subor.split()
        vysledok[int(key)] = val
    return vysledok

#funkcia volana z mainu, pri vypise arp komunikacii vypise konkretne komunikacie pre poslany key pre request
def vypisRequesty(key):
    arpFile.write(str(requesty[key]))

#funkcia volana z mainu, pri vypise arp komunikacii vypise konkretne komunikacie pre poslany key pre reply
def vypisReply(key):
    arpFile.write(str(reply[key]))

#funkcia volana z mainu, ukladam si do dict reply a requesty jednotlive udaje na vypis arp komunikacii
def vypisArp(opCode, pocetRamcov, dlzkaRamca, etherAleboIe, targetIp, targetMac, senderMac, senderIp, vypisPacket):
    etherAleboIePom = int(etherAleboIe, 16)
    dlzkaRamcaPom = 0
    pomocna = 0
    #skontorlujem ci to je arp
    if (etherAleboIePom > 1500):
        try:
            if (ethernetTypes[etherAleboIePom] == 'ARP'):
                pomocna = 1
        except KeyError:
            file.write("")

    if (dlzkaRamca < 60):
        dlzkaRamcaPom = 64
    else:
        dlzkaRamcaPom = dlzkaRamca + 4
    #ak je to 0001 tak je to arp request a ukladam si do dict vsetky potrebne udaje na vypis
    # ak je to 0002 tak je to arp reply a ukladam si do dict vsetky potrebne udaje na vypis
    if (pomocna == 1):
        if (opCode == '0001'):
            if (senderIp, targetIp, senderMac) in requesty:
                requesty[senderIp, targetIp, senderMac] += ("\n" + "ramec " + str(pocetRamcov) + "\n")
                requesty[senderIp, targetIp, senderMac] += ("dlzka ramca poskytnuta pcap API – " + str(dlzkaRamca) + " B")
                requesty[senderIp, targetIp, senderMac] += "\n"
                requesty[senderIp, targetIp, senderMac] += ("dlzka ramca prenasaneho po mediu – " + str(dlzkaRamcaPom) + " B")
                requesty[senderIp, targetIp, senderMac] += "\n"
                requesty[senderIp, targetIp, senderMac] += ("Ethernet II" + "\n")
                requesty[senderIp, targetIp, senderMac] += ("ARP" + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Cielova IP: " + targetIp + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Zdrojova IP: " + senderIp + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Cielova MAC: " + targetMac + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Zdrojova MAC: " + senderMac + "\n")
                requesty[senderIp, targetIp, senderMac] += (vypisPacket + "\n")
            else:
                requesty[senderIp, targetIp, senderMac] = ("\n" + "ramec " + str(pocetRamcov) + "\n")
                requesty[senderIp, targetIp, senderMac] += ("dlzka ramca poskytnuta pcap API – " + str(dlzkaRamca) + " B")
                requesty[senderIp, targetIp, senderMac] += "\n"
                requesty[senderIp, targetIp, senderMac] += ("dlzka ramca prenasaneho po mediu – " + str(dlzkaRamcaPom) + " B")
                requesty[senderIp, targetIp, senderMac] += "\n"
                requesty[senderIp, targetIp, senderMac] += ("Ethernet II" + "\n")
                requesty[senderIp, targetIp, senderMac] += ("ARP" + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Cielova IP: " + targetIp + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Zdrojova IP: " + senderIp + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Cielova MAC: " + targetMac + "\n")
                requesty[senderIp, targetIp, senderMac] += ("Zdrojova MAC: " + senderMac + "\n")
                requesty[senderIp, targetIp, senderMac] += (vypisPacket + "\n")
        if (opCode == '0002'):
            if (targetIp, senderIp, targetMac) in reply:
                reply[targetIp, senderIp, targetMac] += ("\n" + "ramec " + str(pocetRamcov) + "\n")
                reply[targetIp, senderIp, targetMac] += ("dlzka ramca poskytnuta pcap API – " + str(dlzkaRamca) + " B")
                reply[targetIp, senderIp, targetMac] += "\n"
                reply[targetIp, senderIp, targetMac] += ("dlzka ramca prenasaneho po mediu – " + str(dlzkaRamcaPom) + " B")
                reply[targetIp, senderIp, targetMac] += "\n"
                reply[targetIp, senderIp, targetMac] += ("Ethernet II" + "\n")
                reply[targetIp, senderIp, targetMac] += ("ARP" + "\n")
                reply[targetIp, senderIp, targetMac] += ("Cielova IP: " + targetIp + "\n")
                reply[targetIp, senderIp, targetMac] += ("Zdrojova IP: " + senderIp + "\n")
                reply[targetIp, senderIp, targetMac] += ("Cielova MAC: " + targetMac + "\n")
                reply[targetIp, senderIp, targetMac] += ("Zdrojova MAC: " + senderMac + "\n")
                reply[targetIp, senderIp, targetMac] += (vypisPacket + "\n")
            else:
                reply[targetIp, senderIp, targetMac] = ("\n" + "ramec " + str(pocetRamcov) + "\n")
                reply[targetIp, senderIp, targetMac] += ("dlzka ramca poskytnuta pcap API – " + str(dlzkaRamca) + " B")
                reply[targetIp, senderIp, targetMac] += "\n"
                reply[targetIp, senderIp, targetMac] += ("dlzka ramca prenasaneho po mediu – " + str(dlzkaRamcaPom) + " B")
                reply[targetIp, senderIp, targetMac] += "\n"
                reply[targetIp, senderIp, targetMac] += ("Ethernet II" + "\n")
                reply[targetIp, senderIp, targetMac] += ("ARP" + "\n")
                reply[targetIp, senderIp, targetMac] += ("Cielova IP: " + targetIp + "\n")
                reply[targetIp, senderIp, targetMac] += ("Zdrojova IP: " + senderIp + "\n")
                reply[targetIp, senderIp, targetMac] += ("Cielova MAC: " + targetMac + "\n")
                reply[targetIp, senderIp, targetMac] += ("Zdrojova MAC: " + senderMac + "\n")
                reply[targetIp, senderIp, targetMac] += (vypisPacket + "\n")


#funkcia je volana z 'main' funkcie
#ak sme na zaciatku dali do inputu 2 a icmp, vypisu sa vsetky icmp do vypisIcmpKomunikacii.txt
#ak je icmp viac ako 20 vypise prvych 10 a poslednych 10, ak je ich <20 vypise vsetky
def vypisIcmp(icmppp, dlzkaRamca, pocetRamcov, etherAleboIe, zdrojova, cielova, ipZdrojova, ipCielova, udpOrTcp, vypisPacket):
    etherAleboIePom = int(etherAleboIe, 16)
    minnn = int(icmppp, 16)
    udpPom = int(udpOrTcp, 16)
    protokolKonkretne = ""
    global icmpCounter
    pomocna = 0

    #zistim ci je to ipv4 a icmp, aby som vedela ci ma zmysel to dalej analyzovat
    if (etherAleboIePom > 1500):
        try:
            if (ethernetTypes[etherAleboIePom] == 'IPv4'):
                pomocna = 1
        except KeyError:
            icmpFile.write("")
    if (pomocna == 1):
        try:
            if (protokolTypes[udpPom] == 'ICMP'):
                protokolKonkretne = "icmp"
        except KeyError:
            icmpFile.write("")
    #ak je to icmp a ipv4 tak idem konkretne vypisovat jednotlive icmp a aj ich blizsie analyzovat
    if (protokolKonkretne == 'icmp' and pomocna == 1):
        if(icmpPocet == 0):
            icmpFile.write("Nie su tu ziadne icmp")
        elif (icmpPocet < 20):
            icmpFile.write("\n" + "ramec " + str(pocetRamcov) + "\n")
            icmpFile.write("dlzka ramca poskytnuta pcap API – ")
            icmpFile.write(str(dlzkaRamca) + " B" + "\n")
            icmpFile.write("dlzka ramca prenasaneho po mediu – ")
            if (dlzkaRamca >= 60):
                icmpFile.write(str(dlzkaRamca + 4) + " B" + "\n")
            else:
                icmpFile.write(str(64) + " B" + "\n")
            if (etherAleboIePom > 1500):
                icmpFile.write("Ethernet II" + "\n")
            icmpFile.write("zdrojova MAC adresa: " + str(zdrojova) + "\n")
            icmpFile.write("cielova MAC adresa: " + str(cielova) + "\n")
            try:
                icmpFile.write(ethernetTypes[etherAleboIePom] + "\n")
            except KeyError:
                icmpFile.write("")
            icmpFile.write("zdrojova IP adresa: " + ipZdrojova + "\n")
            icmpFile.write("cielova IP adresa: " + ipCielova + "\n")
            try:
                icmpFile.write(icmpTypes[minnn] + "\n")
            except KeyError:
                icmpFile.write("")
            icmpFile.write(vypisPacket)
        else:
            #icmpCounter mi pocita, kolko ramcov som uz vypisala, a reguluje vypis prvych a poslednych 10 icmp
            icmpCounter += 1
            if (icmpCounter <= 10 or icmpCounter > icmpPocet-10):
                icmpFile.write("\n" + "ramec " + str(pocetRamcov) + "\n")
                icmpFile.write("dlzka ramca poskytnuta pcap API – ")
                icmpFile.write(str(dlzkaRamca) + " B" + "\n")
                icmpFile.write("dlzka ramca prenasaneho po mediu – ")
                if (dlzkaRamca >= 60):
                    icmpFile.write(str(dlzkaRamca + 4) + " B" + "\n")
                else:
                    icmpFile.write(str(64) + " B" + "\n")
                if (etherAleboIePom > 1500):
                    icmpFile.write("Ethernet II" + "\n")
                icmpFile.write("zdrojova MAC adresa: " + str(zdrojova) + "\n")
                icmpFile.write("cielova MAC adresa: " + str(cielova) + "\n")
                try:
                    icmpFile.write(ethernetTypes[etherAleboIePom] + "\n")
                except KeyError:
                    icmpFile.write("")
                icmpFile.write("zdrojova IP adresa: " + ipZdrojova + "\n")
                icmpFile.write("cielova IP adresa: " + ipCielova + "\n")
                icmpFile.write(protokolTypes[1] + "\n")
                try:
                    icmpFile.write(icmpTypes[minnn] + "\n")
                except KeyError:
                    icmpFile.write("")
                icmpFile.write(vypisPacket)

#fukncia volana z httpVypis - vypisuje konkretne ramce komunikacie
def httpVypis(pocetRamcov,dlzkaRamca,etherAleboIe, zdrojova, cielova, ipZdrojova, ipCielova, srcPort, dstPort, udpOrTcp):
    global bolean
    global counter
    etherAleboIePom = int(etherAleboIe, 16)
    if (bolean == 1):
        fileKom.write("Komunikacia c." + str(counter) + "\n")
        fileKom.write("zdrojova IP adresa: " + ipZdrojova + "\n")
        fileKom.write("cielova IP adresa: " + ipCielova + "\n")
        fileKom.write("zdrojovy port: " + str(srcPort) + "\n")
        fileKom.write("cielovy port : " + str(dstPort) + "\n")
        fileKom.write("\n\n")
        bolean = 0
    fileKom.write("ramec " + str(pocetRamcov) + "\n")
    fileKom.write("dlzka ramca poskytnuta pcap API – ")
    fileKom.write(str(dlzkaRamca) + " B" + "\n")
    fileKom.write("dlzka ramca prenasaneho po mediu – ")
    if (dlzkaRamca >= 60):
        fileKom.write(str(dlzkaRamca + 4) + " B" + "\n")
    else:
        fileKom.write(str(64) + " B" + "\n")
    if (etherAleboIePom > 1500):
        fileKom.write("Ethernet II" + "\n")
    fileKom.write("zdrojova MAC adresa: " + str(zdrojova) + "\n")
    fileKom.write("cielova MAC adresa: " + str(cielova) + "\n")
    try:
        fileKom.write(ethernetTypes[etherAleboIePom] + "\n")
    except KeyError:
        fileKom.write("")
    fileKom.write("zdrojova IP adresa: " + ipZdrojova + "\n")
    fileKom.write("cielova IP adresa: " + ipCielova + "\n")
    fileKom.write("zdrojovy port: " + str(srcPort) + "\n")
    fileKom.write("cielovy port : " + str(dstPort) + "\n")
    fileKom.write(vypisPacket)
    fileKom.write("\n\n")

#fukncia volana z 'main' - vypise jednu http kominukaciu
def vypisKom(res,pocetRamcov,dlzkaRamca,temp2, etherAleboIe, zdrojova, cielova, typIeee, ipZdrojova, ipCielova, sourcePort, destinationPort, udpOrTcp):
    udpPom = int(udpOrTcp, 16)
    protokolKonkretne = ""
    etherAleboIePom = int(etherAleboIe, 16)
    srcPort = int(sourcePort, 16)
    dstPort = int(destinationPort, 16)
    pomocna = 0
    global bolean2
    global porty
    global porty2
    global boolean3

    if (etherAleboIePom > 1500):
        try:
            if (ethernetTypes[etherAleboIePom] == 'IPv4'):
                pomocna = 1
        except KeyError:
            file.write("")

    try:
        if (protokolTypes[udpPom] == 'TCP'):
            protokolKonkretne = "tcp"
    except KeyError:
        file.write("")

    if(protokolKonkretne == 'tcp' and pomocna == 1 and srcPort != 0 and dstPort != 0):
        if (bolean2 == 1 and res == '00010'):
            synKontrola = 0
            syns = res
            porty = dstPort
            porty2 = srcPort
            bolean2 = 0

        if (temp2 == "http" and (dstPort == porty or dstPort == porty2) and (srcPort == porty or srcPort == porty2)):
            httpVypis(pocetRamcov, dlzkaRamca, etherAleboIe, zdrojova, cielova, ipZdrojova, ipCielova, srcPort, dstPort, udpOrTcp)

        if (boolean3 == 1 and res == '00001'):
            if ((dstPort == porty or dstPort == porty2) and (srcPort == porty or srcPort == porty2)):
                fileKom.write("uplna komunikacia" + "\n")
                boolean3 = 0
            else:
                fileKom.write("neuplna komunikacia" + "\n")
                boolean3 = 0

#fukncia je volana z funkcie vypis
#do dict si uklada ako key ip adresy a zvysuje ich hodnoty ak sa tam uz raz vyskytli
#vrati vsetky ip adresy ake sa tam vyskytli aj kolkokrat sa tam vyskytli
def vysielajuce(adresa):
    if (adresa in vysielajuceIp):
        vysielajuceIp[adresa] += 1
    else:
        vysielajuceIp[adresa] = 1


#funkcia je volana z 'main' funkcie
#ak sme na zaciatku dali do inputu 1, vypise sa bod 1, 2 a 3 do textovySubor
def vypis(etherAleboIe, zdrojova, cielova, typIeee, ipZdrojova, ipCielova, sourcePort, destinationPort, udpOrTcp, vypisPacket, icmppp):
    etherAleboIePom = int(etherAleboIe, 16)
    typIeeePom = int(typIeee, 16)
    srcPort = int(sourcePort, 16)
    dstPort = int(destinationPort, 16)
    udpPom = int(udpOrTcp, 16)
    icmpPom = int(icmppp, 16)
    protokolKonkretne = ""
    ieeeKonkretne = ""
    pomocna = 0
    pomocnaIE = 0
    #vypis ci to je ethernet alebo ieee
    if (etherAleboIePom > 1500):
        file.write("Ethernet II" + "\n")
    else:
        file.write("IEEE 802.3 ")
        pomocnaIE = 2
        if (typIeeePom == 255):
            file.write("- RAW")
            ieeeKonkretne = "IPX"
        elif (typIeeePom == 170):
            file.write("LLC + SNAP")
        else:
            file.write("LLC ")
            try:
                file.write(llcTypes[typIeeePom])
            except KeyError:
                file.write("")
        file.write("\n")
    #vypis zdrojove a cielovej MAC adresy a konkretneho typu ethernet (z ethernet.txt) alebo llc (z llc.txt)
    file.write("zdrojova MAC adresa: " + str(zdrojova) + "\n")
    file.write("cielova MAC adresa: " + str(cielova) + "\n")
    if (etherAleboIePom > 1500):
        try:
            file.write(ethernetTypes[etherAleboIePom] + "\n")
            if (ethernetTypes[etherAleboIePom] == 'IPv4'):
                pomocna = 1
            if (ethernetTypes[etherAleboIePom] == 'ARP'):
                pomocna = 5
        except KeyError:
            file.write("")
    if (ieeeKonkretne != ""):
        file.write(ieeeKonkretne + "\n")
        ieeeKonkretne = ""
    # ak je to ethernet a ipv4 vypise zdrojovu a cielovu ip a spocita pri nich adresu vysielajucich uzlov
    #zistim si aj konkretne typy protokolov z protokol.txt externeho suboru
    if(pomocna == 1):
        file.write("zdrojova IP adresa: " + ipZdrojova + "\n")
        file.write("cielova IP adresa: " + ipCielova + "\n")
        vysielajuce(ipCielova)
        try:
            file.write(protokolTypes[udpPom] + "\n")
            if (protokolTypes[udpPom] == 'TCP'):
                protokolKonkretne = "tcp"
            if (protokolTypes[udpPom] == 'UDP'):
                protokolKonkretne = "udp"
            if (protokolTypes[udpPom] == 'ICMP'):
                protokolKonkretne = "icmp"
        except KeyError:
            file.write("")
    #vypisem konkretne typy udp (udp.txt), tcp (txp.txt) a icmp(txmp.txt) z externych textovych suborov
    if (srcPort != 0 and dstPort != 0 and pomocnaIE != 2 and pomocna == 1):
        file.write("zdrojovy port: " + str(srcPort) + "\n")
        file.write("cielovy port: " + str(dstPort) + "\n")
        if (protokolKonkretne == 'udp'):
            if (srcPort > dstPort):
                try:
                    file.write(udpTypes[dstPort] + "\n")
                except KeyError:
                    file.write("")
            else:
                try:
                    file.write(udpTypes[srcPort] + "\n")
                except KeyError:
                    file.write("")
        if (protokolKonkretne == 'tcp'):
            if (srcPort > dstPort):
                try:
                    file.write(tcpTypes[dstPort] + "\n")
                except KeyError:
                    file.write("")
            else:
                try:
                    file.write(tcpTypes[srcPort] + "\n")
                except KeyError:
                    file.write("")
        if (protokolKonkretne == 'icmp'):
            if (srcPort > dstPort):
                try:
                    file.write(icmpTypes[icmpPom] + "\n")
                except KeyError:
                    file.write("")
            else:
                try:
                    file.write(icmpTypes[icmpPom] + "\n")
                except KeyError:
                    file.write("")
    #vypis packetov po bajtoch
    file.write(vypisPacket)
    file.write("\n" + "---------------------------------" + "\n")


#tu zacina moj main
#na zaciatku zada bud 1 - ak chce bod 1,2,3 alebo 2 ak chce nejake komunikacie + konkretnu kominukaciu a nazov pcap
temp2 = ""
temp = input("Zadaj, co chces urobit -> 1: vypise bod1,2,3; 2: vypis komunikacie - vypise bod 4a,4h,4i ---> ")
if (temp == '2'):
    temp2 = input("Zadaj konkretnu komunikaciu(http, icmp, arp): ")
temp1 = input("Zadaj nazov pcap suboru(eth-1, trace-26): ")
temp1 = temp1 + ".pcap"
print("Idu sa analyzovat data z: " + temp1)

packets = rdpcap(temp1)
file = open("textovySubor.txt", "w")
fileKom = open("komunikacia.txt", "w")
arpFile = open("vypisArpKomunikacii.txt", "w")
icmpFile = open("vypisIcmpKomunikacii.txt", "w")
#do nasledujucich Types si nacitam vsetko co je v danych suborov, pomocou key-value
ethernetTypes = nacitajSubory("ethernet.txt")
llcTypes = nacitajSubory("llc.txt")
udpTypes = nacitajSubory("udp.txt")
tcpTypes = nacitajSubory("tcp.txt")
icmpTypes = nacitajSubory("icmp.txt")
protokolTypes = nacitajSubory("protokol.txt")

pocetRamcov = 1
splits = ""
dlzkaRamca = 0
cielova = ""
zdrojova = ""
etherAleboIe = ""
vypisPacket = ""
typIeee = ""
ipZdroj = ""
ipZdrojPom = 0
ipZdrojova = ""
ipCiel = ""
ipCielPom = 0
ipCielova = ""
sourcePort = ""
destinationPort = ""
pomocnyPacket = ""
listy = ""
udpOrTcp = ""
ipHlavickaZaciatok = 0
ipHlavicka = ""
pocitadlo = 0
ip = ""
tcpKonkretne = 0
prve = ""
druhe = ""
tcpNazov = ""
ramecTcp = 0
syn = ""
syny = ""
pomm = 1
res = ""
sequenceNumber = ""
ackNumber= ""
ramecdlzka = 0
packety = 0
icmppp = ""
minimum = 0
opCode = ""
senderIp = ""
targetIp = ""
senderMac = ""
targetMac = ""

#prejdem vsetky ramce, aby som zistila, kolko icmp sa tam nachadza
if (temp2 == 'icmp'):
    for packet in packets:
        packety = packety + 1
        pomocnyPacket = hexstr(packet)
        splits = pomocnyPacket.split(" ")
        for split in splits:
            if (split != ''):
                listy = listy + split + " "
            else:
                break
        lists = listy.split(" ")
        for list in lists:
            if (list != ''):
                ramecdlzka = ramecdlzka + 1
                if (ramecdlzka == 13 or ramecdlzka == 14):
                    etherAleboIe = etherAleboIe + list
                if (ramecdlzka == 24):
                    udpOrTcp = list
            else:
                if (etherAleboIe == '0800' and udpOrTcp == '01'):
                    icmpPocet += 1
                etherAleboIe = ""
                udpOrTcp = ""
                ramecdlzka = 0
        lists = ""
        listy = ""

pocetRamcov = 1
splits = ""
dlzkaRamca = 0
etherAleboIe = ""
udpOrTcp = ""

#packet je jeden riadok vo wiresharku = 1 ramec
for packet in packets:
    if(temp == '1'):
        file.write("ramec ")
        file.write(str(pocetRamcov))
        file.write("\n")
    #do pomocnyPacket si ulozim iba hexadecimalne cislo bez \x
    pomocnyPacket = hexstr(packet)
    #pomocou split si ich porozdelujem na jednotlive stringy
    splits = pomocnyPacket.split(" ")
    #orezem na konci podivne znaky (neboli v hexa tvare) a necham si iba tie bajty, s ktorymi budem pracovat
    for split in splits:
        if (split != ''):
            listy = listy + split + " "
        else:
            break
    #prechadzam jednotlive bajty a ukladam si tie, ktore budem potrebovat na vypis alebo vypocet
    lists = listy.split(" ")
    for list in lists:
        if (list != ''):
            dlzkaRamca = dlzkaRamca + 1

            if(dlzkaRamca > 15 and tcpKonkretne != 0 and dlzkaRamca == 15+tcpKonkretne):
                tcpNazov = tcpNazov + list
                ramecTcp = dlzkaRamca
                if (minimum == 0):
                    icmppp = list

            if (dlzkaRamca <= 6):
                cielova = cielova + list + " "

            if (dlzkaRamca > 6 and dlzkaRamca < 13):
                zdrojova = zdrojova + list + " "

            if (dlzkaRamca == 13 or dlzkaRamca == 14):
                etherAleboIe = etherAleboIe + list

            if (dlzkaRamca == 21 or dlzkaRamca == 22):
                opCode = opCode + list

            if (dlzkaRamca == 15):
                typIeee = typIeee + list
                ipHlavicka = list
                li = [(ipHlavicka[i:i + 1]) for i in range(0, len(ipHlavicka), 1)]
                for l in li:
                    if (pocitadlo == 1):
                        druhe = l
                        break
                    prve = l
                    pocitadlo = 1

                prveCislo = int(prve, 16)
                druheCislo = int(druhe, 16)
                tcpKonkretne = prveCislo * druheCislo
                if (tcpKonkretne+15 < 20):
                    minimum = 1

            if (dlzkaRamca == 35 and minimum == 1):
                icmppp = list

            if (dlzkaRamca > 26 and dlzkaRamca < 31):
                ipZdrojPom = int(list, 16)
                if (dlzkaRamca == 30):
                    ipZdrojova = ipZdrojova + str(ipZdrojPom)
                else:
                    ipZdrojova = ipZdrojova + str(ipZdrojPom) + "."

            if (dlzkaRamca == 24):
                udpOrTcp = list

            if ((dlzkaRamca == ramecTcp + 12 or dlzkaRamca == ramecTcp + 13) and ramecTcp != 0):
                syn = syn + list

            if (dlzkaRamca == 39 or dlzkaRamca == 40 or dlzkaRamca == 41 or dlzkaRamca == 42):
                sequenceNumber = sequenceNumber + list

            if (dlzkaRamca == 43 or dlzkaRamca == 44 or dlzkaRamca == 45 or dlzkaRamca == 46):
                ackNumber = ackNumber + list

            if (dlzkaRamca == 29 or dlzkaRamca == 30 or dlzkaRamca == 31 or dlzkaRamca == 32):
                if(dlzkaRamca == 32):
                    senderIp = senderIp + str(int(list, 16))
                else:
                    senderIp = senderIp + str(int(list,16)) + "."

            if (dlzkaRamca == 23 or dlzkaRamca == 24 or dlzkaRamca == 25 or dlzkaRamca == 26 or dlzkaRamca == 27 or dlzkaRamca == 28):
                if (dlzkaRamca == 28):
                    senderMac = senderMac + str(int(list,16))
                else:
                    senderMac = senderMac + str(int(list,16)) + "."

            if (dlzkaRamca == 33 or dlzkaRamca == 34 or dlzkaRamca == 35 or dlzkaRamca == 36 or dlzkaRamca == 37 or dlzkaRamca == 38):
                if (dlzkaRamca == 38):
                    targetMac = targetMac + str(int(list,16))
                else:
                    targetMac = targetMac + str(int(list, 16)) + "."

            if (dlzkaRamca == 39 or dlzkaRamca == 40 or dlzkaRamca == 41 or dlzkaRamca == 42):
                if (dlzkaRamca == 42):
                    targetIp = targetIp + str(int(list,16))
                else:
                    targetIp = targetIp + str(int(list, 16))+ "."

            if (dlzkaRamca > 30 and dlzkaRamca < 35):
                ipCielPom = int(list, 16)
                if (dlzkaRamca == 34):
                    ipCielova = ipCielova + str(ipCielPom)
                else:
                    ipCielova = ipCielova + str(ipCielPom) + "."

            if (dlzkaRamca == 35 or dlzkaRamca == 36):
                sourcePort = sourcePort + list

            if (dlzkaRamca == 37 or dlzkaRamca == 38):
                destinationPort = destinationPort + list

            if (dlzkaRamca % 16 == 0):
                vypisPacket = vypisPacket + list + "\n"
            elif (dlzkaRamca % 8 == 0):
                vypisPacket = vypisPacket + list + "  "
            else:
                vypisPacket = vypisPacket + list + " "
        else:
            #ukladam si flags do binarneho tvaru o dlzke 5 bitov
            lii = [(syn[i:i + 1]) for i in range(0, len(syn), 1)]
            for l in lii:
                if (pomm == 1):
                    pomm = 0
                    continue
                syny = syny + l
                res = "{0:05b}".format(int(syny, 16))
            #ak sme na zaciatku zadali do inputu 1 ide sa vykonavat tato podmienka
            if (temp == '1'):
                file.write("dlzka ramca poskytnuta pcap API – ")
                file.write(str(dlzkaRamca) + " B" + "\n")
                file.write("dlzka ramca prenasaneho po mediu – ")
                if (dlzkaRamca >= 60):
                    file.write(str(dlzkaRamca + 4) + " B" + "\n")
                else:
                    file.write(str(64) + " B" + "\n")
                vypis(etherAleboIe, zdrojova, cielova, typIeee, ipZdrojova, ipCielova, sourcePort, destinationPort, udpOrTcp, vypisPacket, icmppp)
            # ak sme na zaciatku zadali do inputu 2 a http ide sa vykonavat tato podmienka
            if (temp2 == 'http'):
                vypisKom(res,pocetRamcov,dlzkaRamca,temp2, etherAleboIe, zdrojova, cielova, typIeee, ipZdrojova, ipCielova, sourcePort, destinationPort, udpOrTcp)
            # ak sme na zaciatku zadali do inputu 2 a icmp ide sa vykonavat tato podmienka
            if (temp2 == 'icmp'):
                vypisIcmp(icmppp, dlzkaRamca, pocetRamcov, etherAleboIe, zdrojova, cielova, ipZdrojova, ipCielova, udpOrTcp, vypisPacket)
            # ak sme na zaciatku zadali do inputu 2 a arp ide sa vykonavat tato podmienka
            if (temp2 == 'arp'):
                vypisArp(opCode, pocetRamcov, dlzkaRamca, etherAleboIe,targetIp, targetMac, senderMac, senderIp, vypisPacket)
            cielova = ""
            zdrojova = ""
            etherAleboIe = ""
            vypisPacket = ""
            typIeee = ""
            ipZdrojova = ""
            ipCielova = ""
            sourcePort = ""
            destinationPort = ""
            dlzkaRamca = 0
            ipHlavicka = ""
            pocitadlo = 0
            tcpNazov = ""
            tcpKonkretne = 0
            syn = ""
            syny = ""
            pomm = 1
            ackNumber = ""
            sequenceNumber = ""
            minimum = 0
            opCode= ""
            senderIp = ""
            targetIp = ""
            senderMac = ""
            targetMac = ""
    pocetRamcov = pocetRamcov + 1
    lists = ""
    listy = ""

# ak sme na zaciatku zadali do inputu 1, na konci suboru vypise adresy uzlov
if(temp == '1'):
    max = 0
    file.write("IP adresy vysielajucich uzlov:" + "\n")
    for key in vysielajuceIp:
        file.write(str(key) + "\n")
    file.write("Adresa uzla s najvacsim poctom prijatych paketov: " + "\n")
    for v in vysielajuceIp.values():
        if (v > max):
            max = v
    file.write(str(max) + " paketov" + "\n")
    for key, value in vysielajuceIp.items():
        if (max == value):
            file.write(str(key))

# ak sme na zaciatku zadali do inputu 2 a arp, do suboru vypisArpKomunikacie vypise arp komunkacie,arp request a reply
if(temp2 == 'arp'):
    for keys in requesty:
        for key in reply:
            if (keys == key):
                arpFile.write("----------Komunikacia cislo: " + str(countArp) + "----------" + "\n")
                arpFile.write("REQUEST" + "\n")
                arpFile.write("zdrojova IP, cielova IP, zdrojova MAC" + "\n")
                arpFile.write(str(key))
                vypisRequesty(keys)
                arpFile.write("\n" + "REPLY" + "\n")
                vypisReply(keys)
                arpFile.write("\n" + "----------Koniec komunikacie cislo: " + str(countArp) + "----------" + "\n")
                countArp += 1
            else:
                arpFile.write("\n" + "REQUEST" + "\n")
                arpFile.write("zdrojova IP , cielova IP, zdrojova MAC" + "\n")
                arpFile.write(str(keys) + "\n")
                vypisRequesty(keys)
                arpFile.write("\n\n")
file.close()