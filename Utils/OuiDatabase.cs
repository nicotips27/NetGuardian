using System.Net.NetworkInformation;

namespace NetGuardian.Utils;

/// <summary>
/// Base de datos OUI (Organizationally Unique Identifier) embebida.
///
/// Los primeros 3 bytes (24 bits) de toda direccion MAC identifican al
/// fabricante registrado ante la IEEE. Contiene los ~200 fabricantes mas
/// comunes en redes domesticas (ordenadores, moviles, IoT, routers...).
/// Fuente: registro oficial IEEE (https://standards-oui.ieee.org/).
/// Se embebe en el codigo para mantener el .exe 100% portable.
/// </summary>
public static class OuiDatabase
{
    // Clave: prefijo "AABBCC" en mayusculas, sin separadores.
    private static readonly Dictionary<string, string> _vendors = new()
    {
        // --- Apple ---
        ["001B63"]="Apple", ["001E52"]="Apple", ["002332"]="Apple",
        ["00236C"]="Apple", ["0025BC"]="Apple", ["002608"]="Apple",
        ["003EE1"]="Apple", ["0050E4"]="Apple", ["040CCE"]="Apple",
        ["041552"]="Apple", ["045453"]="Apple", ["04D3CF"]="Apple",
        ["04F7E4"]="Apple", ["0C3021"]="Apple", ["0C4DE9"]="Apple",
        ["0C74C2"]="Apple", ["103047"]="Apple", ["1093E9"]="Apple",
        ["14109F"]="Apple", ["14459F"]="Apple", ["14BD61"]="Apple",
        ["183451"]="Apple", ["189EFC"]="Apple", ["1C1AC0"]="Apple",
        ["203CAE"]="Apple", ["24AB81"]="Apple", ["283737"]="Apple",
        ["28A02B"]="Apple", ["2C1F23"]="Apple", ["3C15C2"]="Apple",
        ["3C2EFF"]="Apple", ["40A6D9"]="Apple", ["40B395"]="Apple",
        ["44FB42"]="Apple", ["4C8D79"]="Apple", ["50EAD6"]="Apple",
        ["5473CB"]="Apple", ["5C5948"]="Apple", ["5CF5DA"]="Apple",
        ["60A4D0"]="Apple", ["645AED"]="Apple", ["6C3E6D"]="Apple",
        ["6C709F"]="Apple", ["6C96CF"]="Apple", ["70CD60"]="Apple",
        ["70ECE4"]="Apple", ["748117"]="Apple", ["78A3E4"]="Apple",
        ["7CF05F"]="Apple", ["84FCFE"]="Apple", ["8C2937"]="Apple",
        ["8CC8CD"]="Apple", ["903C92"]="Apple", ["9803D8"]="Apple",
        ["9C293F"]="Apple", ["A01828"]="Apple", ["A4B197"]="Apple",
        ["A4C361"]="Apple", ["A85B78"]="Apple", ["AC293A"]="Apple",
        ["AC7F3E"]="Apple", ["B065BD"]="Apple", ["B418D1"]="Apple",
        ["B853AC"]="Apple", ["BC3BAF"]="Apple", ["BC6778"]="Apple",
        ["C0A53E"]="Apple", ["C8BCD8"]="Apple", ["D023DB"]="Apple",
        ["D461DA"]="Apple", ["D8A71D"]="Apple", ["DC0C5C"]="Apple",
        ["E0B9BA"]="Apple", ["E4C63D"]="Apple", ["E8802E"]="Apple",
        ["F0B479"]="Apple", ["F0D1A9"]="Apple", ["F81EDF"]="Apple",
        // --- Samsung ---
        ["0023D6"]="Samsung", ["0023D7"]="Samsung", ["0024E9"]="Samsung",
        ["0425C5"]="Samsung", ["0C1437"]="Samsung", ["101DC0"]="Samsung",
        ["14A364"]="Samsung", ["1C62B8"]="Samsung", ["24C44A"]="Samsung",
        ["2C0E3D"]="Samsung", ["30CDA7"]="Samsung", ["3423BA"]="Samsung",
        ["3825DF"]="Samsung", ["5056BF"]="Samsung", ["5CE8EB"]="Samsung",
        ["606BBD"]="Samsung", ["649010"]="Samsung", ["6C2F2C"]="Samsung",
        ["846866"]="Samsung", ["8C77AB"]="Samsung", ["90F1AA"]="Samsung",
        ["988389"]="Samsung", ["A0B4A5"]="Samsung", ["A8F274"]="Samsung",
        ["B0C4E7"]="Samsung", ["B437D1"]="Samsung", ["C432D1"]="Samsung",
        ["CC07AB"]="Samsung", ["D052A8"]="Samsung", ["D8E0E1"]="Samsung",
        ["E0DB10"]="Samsung", ["E8508B"]="Samsung", ["EC107B"]="Samsung",
        ["F8042E"]="Samsung",
        // --- Google (Pixel, Nest, Chromecast) ---
        ["1C72A4"]="Google", ["28246F"]="Google", ["3C28A6"]="Google",
        ["546009"]="Google", ["94EB2C"]="Google",
        ["F4F5D8"]="Google", ["F88FCA"]="Google",
        // --- Xiaomi / Redmi ---
        ["0C1DAF"]="Xiaomi", ["186672"]="Xiaomi", ["20DD9F"]="Xiaomi",
        ["286C07"]="Xiaomi", ["4898CA"]="Xiaomi", ["5C022E"]="Xiaomi",
        ["681AB2"]="Xiaomi", ["7C1EB9"]="Xiaomi", ["903A72"]="Xiaomi",
        ["98FAE3"]="Xiaomi", ["AC8506"]="Xiaomi", ["B0E235"]="Xiaomi",
        ["E498D6"]="Xiaomi", ["F0B429"]="Xiaomi", ["FCF136"]="Xiaomi",
        // --- Huawei / Honor ---
        ["045148"]="Huawei", ["0C96CD"]="Huawei", ["28A6DB"]="Huawei",
        ["485FDF"]="Huawei", ["5C4CA9"]="Huawei", ["6841DC"]="Huawei",
        ["740431"]="Huawei", ["840F45"]="Huawei", ["9CD24B"]="Huawei",
        ["ACE430"]="Huawei", ["CC96A0"]="Huawei", ["E4FC82"]="Huawei",
        // --- PC / placas base: Intel ---
        ["001302"]="Intel", ["0013E8"]="Intel",
        ["001B77"]="Intel", ["001E67"]="Intel", ["00215D"]="Intel",
        ["00BB60"]="Intel", ["081196"]="Intel", ["0C8BFD"]="Intel",
        ["183D5E"]="Intel", ["1C1BB5"]="Intel", ["2887BA"]="Intel",
        ["3484E4"]="Intel", ["44870C"]="Intel", ["4851C5"]="Intel",
        ["4C3488"]="Intel", ["5CD26A"]="Intel", ["7054F5"]="Intel",
        ["74DA38"]="Intel", ["7C67A2"]="Intel", ["8C8D28"]="Intel",
        ["942865"]="Intel", ["A036BC"]="Intel", ["B40EDE"]="Intel",
        ["CC2F71"]="Intel", ["D0ABD5"]="Intel", ["E0A8B8"]="Intel",
        ["F89E94"]="Intel",
        // --- Realtek ---
        ["4CE173"]="Realtek", ["748A0D"]="Realtek", ["80FA5B"]="Realtek",
        ["F0DEF1"]="Realtek", ["40490F"]="Realtek", ["70610B"]="Realtek",
        // --- Broadcom ---
        ["001018"]="Broadcom", ["001BE9"]="Broadcom", ["20FA3E"]="Broadcom",
        // --- Atheros / Qualcomm ---
        ["000314"]="Qualcomm Atheros", ["00156D"]="Qualcomm Atheros",
        ["9CD643"]="Qualcomm Atheros",
        // --- Microsoft ---
        ["002248"]="Microsoft", ["28AEA9"]="Microsoft",
        ["383F10"]="Microsoft", ["7C1E52"]="Microsoft", ["B87937"]="Microsoft",
        ["DCB984"]="Microsoft",
        // --- Dell ---
        ["00065B"]="Dell", ["001143"]="Dell", ["0019B9"]="Dell",
        ["001D09"]="Dell", ["00215C"]="Dell", ["005056"]="VMware",
        ["14301E"]="Dell", ["246E96"]="Dell", ["784476"]="Dell",
        ["B0829F"]="Dell", ["D067E5"]="Dell",
        // --- HP / HPE ---
        ["0004EA"]="HP", ["0010E3"]="HP", ["001560"]="HP",
        ["0019BB"]="HP", ["00215A"]="HP", ["0CDEFF"]="HP",
        ["308D99"]="HP", ["9457A5"]="HP", ["A0D3C1"]="HP",
        ["D05F64"]="HP", ["EC846A"]="HP",
        // --- Lenovo ---
        ["00CDFE"]="Lenovo", ["40F2E9"]="Lenovo", ["6C2B59"]="Lenovo",
        ["7C05BC"]="Lenovo", ["8C166F"]="Lenovo", ["C4E086"]="Lenovo",
        // --- ASUSTek ---
        ["0011D8"]="ASUS", ["0015F2"]="ASUS", ["001FC6"]="ASUS",
        ["04D9F5"]="ASUS", ["107B44"]="ASUS", ["843A4B"]="ASUS",
        // --- Acer ---
        ["000AE4"]="Acer", ["0016D3"]="Acer", ["6C2A85"]="Acer",
        // --- MSI / Gigabyte ---
        ["001DBA"]="MSI", ["D43D7E"]="Micro-Star (MSI)",
        // --- Routers: TP-Link ---
        ["002586"]="TP-Link", ["105A17"]="TP-Link", ["30FC68"]="TP-Link",
        ["50BD5F"]="TP-Link", ["584387"]="TP-Link", ["6C5AB0"]="TP-Link",
        ["849AB5"]="TP-Link", ["A0F3C1"]="TP-Link", ["C025E9"]="TP-Link",
        ["D4016D"]="TP-Link", ["EC086B"]="TP-Link", ["F81A67"]="TP-Link",
        // --- Netgear ---
        ["000FB5"]="Netgear", ["00146C"]="Netgear", ["001B2F"]="Netgear",
        ["204E7F"]="Netgear", ["4494FC"]="Netgear", ["8416F9"]="Netgear",
        ["B03956"]="Netgear", ["E0F847"]="Netgear",
        // --- D-Link ---
        ["001195"]="D-Link", ["001CF0"]="D-Link", ["00265A"]="D-Link",
        ["340804"]="D-Link", ["78D66F"]="D-Link", ["C03F0E"]="D-Link",
        // --- Cisco / Linksys ---
        ["0001C9"]="Cisco", ["000393"]="Cisco", ["0014A2"]="Cisco",
        ["589835"]="Meraki (Cisco)", ["E05F45"]="Cisco",
        // --- Ubiquiti ---
        ["60D327"]="Ubiquiti", ["788A20"]="Ubiquiti", ["941866"]="Ubiquiti",
        // --- Movistar / ONTs comunes en Espana ---
        ["F4ABEF"]="Movistar/Ont", ["00D0F6"]="Movistar/Ont",
        // --- Sagemcom (routers de operadoras: Orange, Movistar...) ---
        ["28DB1E"]="Sagemcom", ["B4B017"]="Sagemcom", ["EC3618"]="Sagemcom",
        // --- Amazon (Echo, Fire, Kindle) ---
        ["34D270"]="Amazon", ["44BB67"]="Amazon", ["5C41A7"]="Amazon",
        ["74E637"]="Amazon", ["AC5A14"]="Amazon", ["FC65DE"]="Amazon",
        // --- Sony (TV, PlayStation) ---
        ["0001D2"]="Sony", ["000D88"]="Sony", ["081196"]="Sony",
        ["78C881"]="Sony", ["D8E750"]="Sony",
        // --- LG ---
        ["001C62"]="LG", ["002599"]="LG", ["10174A"]="LG",
        ["300D43"]="LG", ["889897"]="LG",
        // --- Vizio / Roku (streaming) ---
        ["ACE2D3"]="Roku", ["060EBD"]="Roku", ["C83A6B"]="Roku",
        ["DC3A5E"]="Roku",
        // --- Espressif (ESP8266/ESP32: domotica, Tasmota, ESPHome) ---
        ["18FE34"]="Espressif", ["240AC4"]="Espressif", ["2CF432"]="Espressif",
        ["30AEA4"]="Espressif", ["5CCF7F"]="Espressif", ["600194"]="Espressif",
        ["8CAAB5"]="Espressif", ["A44E31"]="Espressif", ["AC67B2"]="Espressif",
        ["C44F33"]="Espressif", ["ECFABC"]="Espressif",
        // --- Raspberry Pi ---
        ["28011C"]="Raspberry Pi", ["B827EB"]="Raspberry Pi", ["DCA632"]="Raspberry Pi",
        // --- Motorola ---
        ["000F9F"]="Motorola", ["40B7F3"]="Motorola Mobility",
        // --- Nokia ---
        ["0026CC"]="Nokia", ["E005C5"]="Nokia",
        // --- Nintendo ---
        ["0009BF"]="Nintendo", ["0022AA"]="Nintendo", ["5C521E"]="Nintendo",
        ["B8AE6E"]="Nintendo",
        // --- Arris (routers/cable modems) ---
        ["0010A4"]="Arris", ["00DD5B"]="Arris",
        // --- ZTE ---
        ["0015EB"]="ZTE", ["987A14"]="ZTE", ["D039B3"]="ZTE",
        // --- VirtualBox ---
        ["080027"]="VirtualBox",
        // --- Parallels / Hyper-V ---
        ["001C42"]="Parallels", ["00155D"]="Hyper-V/Microsoft",
    };

    /// <summary>
    /// Devuelve el fabricante a partir de la MAC, o null si el prefijo
    /// no esta en la base embebida. Detecta tambien MACs locales/privadas.
    /// </summary>
    public static string? GetVendor(PhysicalAddress mac)
    {
        var b = mac.GetAddressBytes();
        if (b.Length < 3) return null;

        // Bit 1 (0x02) del primer byte = direccion localmente administrada
        // (típico de MACs randomizeadas de Android/iPhone, VMs, etc.)
        bool local = (b[0] & 0x02) != 0;
        var prefix = $"{b[0]:X2}{b[1]:X2}{b[2]:X2}";

        if (_vendors.TryGetValue(prefix, out var vendor))
            return local ? $"{vendor} (MAC privada)" : vendor;
        return local ? "MAC privada/aleatoria" : null;
    }
}
