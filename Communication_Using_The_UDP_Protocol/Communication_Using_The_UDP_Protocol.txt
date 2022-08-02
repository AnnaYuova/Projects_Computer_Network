import socket
import struct
import crcmod
import os

# nacitanie zo vstupu ci bude klient alebo server
vstup = input('Zadaj server alebo klient: ')
counter = 0
spravy_pole = []
pole_straty = []
prijaty_subor = []
pole_chybne = []
bytes_policko = []
pocet_chybnych = 0
dict = {}
count = 0
cela_veta = []
pole_chybajuce = []
pole_poradie = []
pole_counter = []
aktualne = 0
chybaju = 0
stratene = 0
neposielaj = 0
vysledna_sprava = ""

# ak chce byt server
if vstup == 'server':
    server_port = input("Zadaj port: 2020 \n")
    server_port = int(server_port)
    server_ip = "127.0.0.1"
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    print("Caka na klienta..")

    #keep alive potvrdenie
    try:
        server_socket.settimeout(40)
        data, addr = server_socket.recvfrom(1472)
        if data.decode() == 'ano':
            print("Keepalive spojenie funguje")
            server_socket.settimeout(None)
    except socket.timeout:
            sprava = "koniec"
            print("Cas vyprsal, klient sa nezapol, vypne sa aj server")
            server_socket.sendto(sprava.encode(), (server_ip, 2021))
            exit()


    # server prijme spravu od klienta, aby nadviazali spojenie
    velkost_hlavicky = struct.calcsize('ciiii')
    data, address = server_socket.recvfrom(1472)
    data = struct.unpack('1ciiii', data[:velkost_hlavicky])

    VELKOST = 0
    CRC = 0
    POCET_FRAGMENTOV = 0
    PORADIE = 0

    # ak som spravu naschval nezmenila - vzdy nadviazu komunikaciu, odoslem znovu klientovi spravu ze uz mozu komunikovat
    if data[0] == b'b':
        print("Server potvrdzuje komunikaciu")
        print("\n\n")
        TYPE = b'z'
        hlavicka_kom = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
        server_socket.sendto(hlavicka_kom, (server_ip, 2021))
    else:
        print("Server nepotvrdzuje komunikaciu a vypina sa")
        exit()

    # v cykle prijmam postupne vsetky fragmenty za sebou ako prichadzaju
    while 1:
        data, address = server_socket.recvfrom(1472)
        hlavicka = struct.unpack('1ciiii', data[:velkost_hlavicky])
        TYPE = hlavicka[0]
        fragmentiky_pocet = hlavicka[1]
        poradie = hlavicka[2]
        pocet_fragmentov = hlavicka[3]
        crc_cislo = hlavicka[4]

        # ak vojde do ifu, tak si iba poslal nazov suboru z klienta, do ktoreho ma ulozit poslany subor
        #rovno si aj vypisem absolutnu cestu k suboru
        if TYPE == b't':
            nazov_suboru = data[velkost_hlavicky:].decode()
            cesta_k_suboru = "C:/Users/Anna/PycharmProjects/pythonProject1"
            cesta_subor = os.path.join(cesta_k_suboru, nazov_suboru)

        # klient prijima spravu od klienta, ze konci a tiez sa vypne
        if TYPE == b'k':
            print("Server dostal, ze klient sa vypina a vypne sa tiez")
            exit()

        #ak pride, ze posiela subor
        if TYPE == b's':
            print("Prijima fragment o velkosti: " + str(fragmentiky_pocet) + "bajtov")
            counter = counter + 1
            dekodovane = data[velkost_hlavicky:]
            pole_poradie.append(poradie)

            # vypocet crc, z toho fragmentu, ktory prisiel, na kontrolu či sa zhodujem s tym crc z hlavicky
            crc_vypocitanie = crcmod.predefined.mkCrcFun('crc-16')
            nove_crc = crc_vypocitanie(data[:velkost_hlavicky - 4] + data[velkost_hlavicky:])

            # ak sa zhoduju crc cisla, rovno si ulozi do pola na index - poradie dany fragment
            # ak sa nerovnaju ulozi si do pola indexov, ktore este musi vyziadat znovu od klienta uz opravene
            if nove_crc == crc_cislo:
                #print("rovnaju sa\n")
                cela_veta.insert(poradie - 1, dekodovane)
            else:
                #print("nerovnaju sa\n")
                pocet_chybnych = pocet_chybnych + 1
                pole_chybne.append(poradie)

            # ak uz dosli vsetky fragmenty a ziadne nie su chybne ide ich rovno vypisat
            if poradie == pocet_fragmentov and not pole_chybne:
                print("Nie su ziadne chybne a rovno ulozi subor (subor bude kompletny po stlaceni k (koniec na strane klienta)")
                file = open(nazov_suboru, 'wb')
                for extrem in range(len(cela_veta)):
                    file.write(bytearray(cela_veta[extrem]))
                print("\nAbsolutna cesta k suboru: ")
                print(os.path.abspath(cesta_subor))
                print("\n")
                pole_poradie = []
                pole_counter = []
                pocet_chybnych = 0
                pole_chybne = []
                cela_veta = []
                counter = 0
                bytes_policko = bytearray(pole_chybne)
                server_socket.sendto(bytes_policko, (server_ip, 2021))

            # ak uz dosli vsetky fragmenty a niektore z nich boli chybne musi ich vyziadat znova
            if poradie == pocet_fragmentov and pole_chybne:
                print("Tieto indexy ziada server znova: ")
                print(pole_chybne)
                bytes_policko = bytearray(pole_chybne)
                server_socket.sendto(bytes_policko, (server_ip, 2021))
                #postupne prijima znovu tie, ktore uz klient posiela spravne
                while 1:
                    data, address = server_socket.recvfrom(1472)
                    hlavicka = struct.unpack('1ciiii', data[:velkost_hlavicky])
                    cela_veta.insert(pole_chybne[count]-1, data[velkost_hlavicky:])
                    count = count + 1
                    if count == len(pole_chybne):
                        pole_chybne = []
                        count = 0
                        break
                print("\n\n\n")

                file = open(nazov_suboru, 'wb')
                print("Chybne sa opravili a ulozi subor (subor bude kompletny po stlaceni k (koniec na strane klienta)")
                for extrem in range(len(cela_veta)):
                    file.write(bytearray(cela_veta[extrem]))
                print("\nAbsolutna cesta k suboru: ")
                print(os.path.abspath(cesta_subor))
                print("\n")
                pole_poradie = []
                pole_counter = []
                cela_veta = []
                pocet_chybnych = 0
                pole_chybne = []
                counter = 0


        # ak pride, ze posiela spravu
        if TYPE == b'p':
            print("Prijima fragment o velkosti: " + str(fragmentiky_pocet) + "bajtov")
            counter = counter + 1
            dekodovane = data[velkost_hlavicky:].decode()
            pole_poradie.append(poradie)

            # vypocet crc, z toho fragmentu, ktory prisiel, na kontrolu či sa zhodujem s tym crc z hlavicky
            crc_vypocitanie = crcmod.predefined.mkCrcFun('crc-16')
            nove_crc = crc_vypocitanie(data[:velkost_hlavicky - 4] + data[velkost_hlavicky:])

            # ak sa zhoduju crc cisla, rovno si ulozi do pola na index - poradie dany fragment
            # ak sa nerovnaju ulozi si do pola indexov, ktore este musi vyziadat znovu od klienta uz opravene
            if nove_crc == crc_cislo:
                #print("rovnaju sa\n")
                dict[poradie] = dekodovane
            else:
                #print("nerovnaju sa\n")
                pocet_chybnych = pocet_chybnych + 1
                pole_chybne.append(poradie)

            # ak uz dosli vsetky ocakavne fragmenty, vytorim si pole od 1- pocet fragmentov
            # toto pole porovnam s polom, kde si ukladam poradia prichadzajuich fragmentov
            # z tychto 2 poli zistim, ktore sa nenchadzaju v oboch a tie viem, ze vynechalo a musim ich vypytat znovu
            if poradie == pocet_fragmentov:
                for i in range(1, pocet_fragmentov + 1):
                    pole_counter.append(i)

                pole_chybajuce = [item for item in pole_counter if item not in pole_poradie]
                print("Tieto indexy vynechalo a musi ich vyziadat znovu od klienta:")
                print(pole_chybajuce)
                print("\n")

                if not pole_chybajuce:
                    print("Vsetko doslo v poriadku a ziadne fragmenty nevynechal\n")
                    chybaju = 1
                else:
                    chybaju = 0

                # posle klientovi, ktore chce znovu
                bytes_pole_chybajuce = bytearray(pole_chybajuce)
                server_socket.sendto(bytes_pole_chybajuce, (server_ip, 2021))

                # ak nejaku chybaju, ide skontrolovat tie nove co dosli, ci su chybne alebo nie
                # tie co su neni chybne si rovno uklada do pola
                # tie chybne si uklada indexy, ktore musi vyziadat znovu, aby ich poslal v spravnom tvare
                if chybaju == 0:
                    while 1:
                        data, address = server_socket.recvfrom(1472)
                        hlavicka = struct.unpack('1ciiii', data[:velkost_hlavicky])
                        crc_chybajuceho = hlavicka[4]

                        crc_vypocitanie = crcmod.predefined.mkCrcFun('crc-16')
                        nove_crc = crc_vypocitanie(data[:velkost_hlavicky - 4] + data[velkost_hlavicky:])

                        if crc_chybajuceho == nove_crc:
                            dict[pole_chybajuce[count]] = data[velkost_hlavicky:].decode()
                        else:
                            pole_chybne.append(pole_chybajuce[count])
                        count = count + 1
                        if count == len(pole_chybajuce):
                            pole_chybajuce = []
                            count = 0
                            aktualne = 1
                            break
                    print("\n\n\n")

            # ak uz dosli vsetky a ziadne nie su chybne rovno ich vypise
            # inak znovu vyziada tie chybne a postupne ich prijima od klienta
            if poradie == pocet_fragmentov and not pole_chybne:
                print("Dosli v poriadku a nie su chybne: ")
                for i in range(1, pocet_fragmentov + 1):
                    vysledna_sprava += dict[i]
                    if i == fragmentiky_pocet:
                        dict = {}
                print(vysledna_sprava)
                bytes_policko = bytearray(pole_chybne)
                server_socket.sendto(bytes_policko, (server_ip, 2021))
                break
            else:
                if poradie == pocet_fragmentov and aktualne == 1:
                    print(pole_chybne)

                    bytes_policko = bytearray(pole_chybne)
                    server_socket.sendto(bytes_policko, (server_ip, 2021))

                    while 1:
                        data, address = server_socket.recvfrom(1472)
                        hlavicka = struct.unpack('1ciiii', data[:velkost_hlavicky])
                        print(data[velkost_hlavicky:].decode())
                        if count == 0:
                            dict[pole_chybne[count]] = data[velkost_hlavicky:].decode()
                            print("Pridava do dict")
                            count = count + 1
                        if count != 0:
                            if data[velkost_hlavicky:].decode() in dict.values():
                                print("Duplikat, nepridava uz")
                            else:
                                dict[pole_chybne[count]] = data[velkost_hlavicky:].decode()
                                print("Pridava do dict")
                                count = count + 1
                        if count == len(pole_chybne):
                            pole_chybne = []
                            count = 0
                            vysledna_sprava = ""
                            break
                    print("\n\n\n")
                    for i in range(1, pocet_fragmentov + 1):
                        vysledna_sprava += dict[i]
                    print(vysledna_sprava)

        # ak boli iba chybne
        if TYPE == b'z':
            print("Tieto indexy dosli chybne a musi ich vyziadat znovu od klienta:")
            print(pole_chybne)
            print("\n")

            #ak nie su ziadne chybne rovno ich vypise
            if not pole_chybne:
                for i in range(1, pocet_fragmentov + 1):
                    vysledna_sprava += dict[i]
                    if i == fragmentiky_pocet:
                        dict = {}
                print(vysledna_sprava)
                bytes_policko = bytearray(pole_chybne)
                server_socket.sendto(bytes_policko, (server_ip, 2021))
                break

            #posle klientovi tie, ktore boli zle
            bytes_policko = bytearray(pole_chybne)
            server_socket.sendto(bytes_policko, (server_ip, 2021))
            # postuone prijima tie chybne, ktore klient posiela znovu ako dobre
            while 1:
                data, address = server_socket.recvfrom(1472)
                hlavicka = struct.unpack('1ciiii', data[:velkost_hlavicky])
                print(data[velkost_hlavicky:].decode())
                if count == 0:
                    dict[pole_chybne[count]] = data[velkost_hlavicky:].decode()
                    print("Pridavam do dict")
                    count = count + 1
                if count != 0:
                    if data[velkost_hlavicky:].decode() in dict.values():
                        print("Duplikat, nepridava uz")
                    else:
                        dict[pole_chybne[count]] = data[velkost_hlavicky:].decode()
                        print("Pridavam do dict")
                        count = count + 1
                if count == len(pole_chybne):
                    pole_chybne = []
                    count = 0
                    vysledna_sprava = ""
                    for i in range(1, pocet_fragmentov + 1):
                        vysledna_sprava += dict[i]
                    print(vysledna_sprava)
                    break
                print("\n\n\n")





# ak si vybere ze chce byt klient
if vstup == 'klient':
    sprava = "ano"
    klient_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    klient_port = input("Zadaj port: 2021\n")
    klient_port = int(klient_port)
    klient_ip = input("Zadaj ip: 127.0.0.1\n")
    klient_socket.bind((klient_ip, klient_port))

    # keep alive - odosle spravu po zapnuti klienta, ze je pritomny
    klient_socket.sendto(sprava.encode(), (klient_ip, 2020))


    # odoslanie spravy serveru na kontorlu ci nadviazali spojenie
    TYPE = b'b'
    VELKOST = 0
    CRC = 0
    POCET_FRAGMENTOV = 0
    PORADIE = 0
    hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
    print("Klient zistuje, ci komunikuju...")
    klient_socket.sendto(hlavicka, (klient_ip, 2020))

    # ak sa na druhej strane zobrazi nezmenena sprava - komunikuju
    data, address = klient_socket.recvfrom(1472)
    data = struct.unpack('1ciiii', data)
    if data[0] == b'z':
        print("Spojenie je nadviazane\n")

    # ak server neodpoveda - vypne sa klient
    if data[0] != b'z':
        print("Server neodpoveda")
        exit()


    while 1:
        # klient sa rozhodne co chce robit, podla toho co chce poslat
        print('Zadaj s (subor), p (sprava), k (koniec): ')
        vstupy = input()

        # ak zada k, skonci a vypne sa aj server aj klient
        if vstupy == 'k':
            TYPE = b'k'
            print("Klient posiela serveru, ze konci a vypne sa")
            hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
            klient_socket.sendto(hlavicka, (klient_ip, 2020))
            exit()

        # ak zada s, odosle subor
        # musi si nacitat zo vstupu nazov suboru a velkost fragmentov
        if vstupy == 's':
            TYPE = b's'
            print("Chce poslat subor")
            kde_je_subor = input('Zadaj nazor suboru\n')
            s = open(kde_je_subor, 'rb')
            subor = s.read()
            upravena_sprava = subor
            velkostFragmentu = input("Zadaj velkost fragmentu:\n")
            print("\nAbsolutna cesta k suboru u klienta: ")
            print(os.path.abspath(kde_je_subor))
            print("\n")

            # subor si rozfragmentuje podla zadaneho cisla
            sprava_pole = [upravena_sprava[i:i + int(velkostFragmentu)] for i in range(0, len(upravena_sprava), int(velkostFragmentu))]

            # zisti pocet framentov
            fragmentiky = len(sprava_pole)

            # vytvorim si nazov suboru, aby som si na druhej strane do neho mohla ulozit poslany subor
            # oddelim priponu suboru a k nazvu pridam '2' a nasledne to zlepim = nazov suboru + 2 + pripona
            pripona = '.'
            pred = kde_je_subor.split('.')[0]
            vysledok = kde_je_subor.partition(pripona)[2]
            nove_meno_suboru = pred + "2" + "." + vysledok

            # poslem serveru novy nazov suboru
            TYPE = b't'
            hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
            zbalene = hlavicka + nove_meno_suboru.encode()
            klient_socket.sendto(zbalene, (klient_ip, 2020))

            POCET_FRAGMENTOV = int(fragmentiky)
            VELKOST = 0
            pocitadlo = 0
            cislo = 1
            TYPE = b's'

            # vypocitam si velkost fragmentov, ktore sa budu odosielat
            # vsetky maju rovnaku velkost zadana velkost fragmentu a posledny bude mat bud rovnaku alebo mensie velkost
            dlzka_spravy = len(kde_je_subor)
            frag = int(velkostFragmentu)
            delenie = dlzka_spravy / frag
            medzi = int(delenie) * frag
            res = dlzka_spravy - medzi

            # v cykle posielam postupne vsetky fragmenty za sebou ako su
            for i in range(0, len(sprava_pole)):
                PORADIE = cislo
                if i == len(sprava_pole)-1:
                    VELKOST = res
                else:
                    VELKOST = int(velkostFragmentu)
                # podla tejto hlavicky bez crc iba vypocitam crc cislo
                ulozena_hlavicka = struct.pack('ciii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV)

                # vypocet crc
                crc_vypocet = crcmod.predefined.mkCrcFun('crc-16')
                CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[i])

                # ak zamerne urobim chybu
                #if i % 2 == 0:
                #   CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[i] + sprava_pole[i - 1])

                # postupne posielam serveru jednotlive fragmenty zabalene spolu s hlavickou
                print("Odosiela fragment o velkosti: " + str(VELKOST) + " bajtov")
                hlavicka = struct.pack('ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                poslanie = hlavicka + sprava_pole[i]
                cislo = cislo + 1
                klient_socket.sendto(poslanie, (klient_ip, 2020))
            print("Dokopy odoslalo spravu na: " + str(fragmentiky) + " fragmentov" + "\n\n")


            # poslem znovu tie chybne ktore ked prisli nesedelo crc a uz ich poslem v spravnom tvare
            data, address = klient_socket.recvfrom(1472)
            chybne = data
            chybne_nove = list(chybne)
            print("Indexy, ktore dosli klientovi, ze ma poslat znova, pretoze dosli chybne: ")
            print(chybne_nove)
            print("\n")
            pocet_chybne = len(chybne)
            if pocet_chybne == 0:
                print("Neboli ziadne chybne a nemusi poslat ziadne")
            else:
                for i in range(0, pocet_chybne):
                    index = chybne_nove[i]
                    index = index - 1
                    print("Klient posiela znovu chybne")
                    ulozena_hlavicka = struct.pack('1ciii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV)

                    crc_vypocet = crcmod.predefined.mkCrcFun('crc-16')
                    CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[index])

                    hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                    poslanie = hlavicka + sprava_pole[index]
                    klient_socket.sendto(poslanie, (klient_ip, 2020))

        # ak zada p, odosle spravu
        # musi si nacitat zo vstupu textovu spravu a velkost fragmentov
        if vstupy == 'p':
            TYPE = b'p'
            print("Chce poslat spravu")
            sprava = input("Zadaj spravu:\n")
            upravena_sprava = sprava
            velkostFragmentu = input("Zadaj velkost fragmentu:\n")

            # subor si rozfragmentuje podla zadaneho cisla
            sprava_pole = [upravena_sprava[i:i + int(velkostFragmentu)] for i in range(0, len(upravena_sprava), int(velkostFragmentu))]

            # zisti pocet framentov
            fragmentiky = len(sprava_pole)

            # vypocitam si velkost fragmentov, ktore sa budu odosielat
            # vsetky maju rovnaku velkost zadana velkost fragmentu a posledny bude mat bud rovnaku alebo mensie velkost
            dlzka_spravy = len(sprava)
            frag = int(velkostFragmentu)
            delenie = dlzka_spravy / frag
            medzi = int(delenie) * frag
            res = dlzka_spravy - medzi

            POCET_FRAGMENTOV = int(fragmentiky)
            VELKOST = 0
            pocitadlo = 0
            PORADIE = 0

            # v cykle posielam postupne vsetky fragmenty za sebou ako su
            for i in range(0, fragmentiky):
                neposielaj = 0
                PORADIE = PORADIE + 1
                if i == fragmentiky-1:
                    VELKOST = res
                else:
                    VELKOST = int(velkostFragmentu)
                # podla tejto hlavicky bez crc iba vypocitam crc cislo
                ulozena_hlavicka = struct.pack('1ciii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV)

                # vypocet crc
                crc_vypocet = crcmod.predefined.mkCrcFun('crc-16')
                CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[pocitadlo].encode())

                # ak zamerne urobim chybu
                if i == 5 or i == 7:
                    CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[pocitadlo].encode() + sprava_pole[pocitadlo - 1].encode())

                # ak naschval vynecham nejaky fragment, aby sa neposlal
                if i == 4:
                    pocitadlo = pocitadlo + 1
                    neposielaj = 1

                # # postupne posielam serveru jednotlive fragmenty, ktore nechcem vynechat zabalene spolu s hlavickou
                if neposielaj == 0:
                    print("Odosiela fragment o velkosti: " + str(VELKOST) + " bajtov")
                    hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                    poslanie = hlavicka + sprava_pole[pocitadlo].encode()
                    pocitadlo = pocitadlo + 1
                    klient_socket.sendto(poslanie, (klient_ip, 2020))
            print("Dokopy odoslalo spravu na: " + str(fragmentiky) + " fragmentov" + "\n\n")

            # doposlem tie co chybaju - boli vynechane
            data, address = klient_socket.recvfrom(1472)
            chybajuce = data
            chybajuce_nove = list(chybajuce)
            print(chybajuce_nove)
            pocet_chybajuce = len(chybajuce)

            # ak ziadne nechybali idem rovno kontrolovat, ktore boli chybne
            # chybajuce posielam rovnako ako pri poielani fragmentov, su zabalene spolu s hlavickou
            if pocet_chybajuce == 0:
                print("Ziadne nechybali, ide rovno skontrolovat chybne")
                TYPE = b'z'
                hlavka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                klient_socket.sendto(hlavka, (klient_ip, 2020))
            else:
                for i in range(0, pocet_chybajuce):
                    index = chybajuce_nove[i]
                    index = index - 1
                    print("Klient posiela znovu, tie co chybali")
                    ulozena_hlavicka = struct.pack('1ciii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV)
                    sprava_pole_bytes = str.encode(sprava_pole[i])

                    crc_vypocet = crcmod.predefined.mkCrcFun('crc-16')
                    CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[index].encode())

                    hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                    poslanie = hlavicka + sprava_pole[index].encode()
                    klient_socket.sendto(poslanie, (klient_ip, 2020))


            # poslem znovu tie chybne ktore ked prisli nesedelo crc a uz ich poslem v spravnom tvare
            data, address = klient_socket.recvfrom(1472)
            chybne = data
            chybne_nove = list(chybne)
            print("Indexy, ktore dosli klientovi, ze ma poslat znova, pretoze dosli chybne: ")
            print(chybne_nove)
            print("\n")
            pocet_chybne = len(chybne)
            if pocet_chybne == 0:
                print("Neboli ziadne chybne a nemusi poslat ziadne")
            else:
                for i in range(0, pocet_chybne):
                    index = chybne_nove[i]
                    index = index - 1
                    print("Klient posiela znovu chybne")
                    ulozena_hlavicka = struct.pack('1ciii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV)
                    sprava_pole_bytes = str.encode(sprava_pole[i])

                    crc_vypocet = crcmod.predefined.mkCrcFun('crc-16')
                    CRC = crc_vypocet(ulozena_hlavicka + sprava_pole[index].encode())

                    hlavicka = struct.pack('1ciiii', TYPE, VELKOST, PORADIE, POCET_FRAGMENTOV, CRC)
                    poslanie = hlavicka + sprava_pole[index].encode()
                    klient_socket.sendto(poslanie, (klient_ip, 2020))


