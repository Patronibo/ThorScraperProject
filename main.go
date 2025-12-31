package main

import (
	"bufio"
	"compress/gzip" // Gzip sıkıştırma ve açma işlemleri için kullanılır.
	"context"       // zaman aşımı, iptal veya değer taşıma gibi işlemler için görevler arasında bağlam sağlar
	"crypto/sha1"   // SHA-1 hash algoritmasını kullanarak verilerin özetini oluşturur
	"encoding/hex"  // byte dizilerini hexadecimal stringe tam tersine dönüştürmek için kullanılır
	"encoding/json" // JSON verilerini serileştirme ve deseralize etme işlemleri için gereklidir
	"fmt"           // konsola yazdırma ve formatlı string işleemlerini yapar
	"io"            // temel giriş çıkış işlemleri için
	"log"           // program içinde loglama ve hata mesajlarını yazdırmak için kullanılır
	"net/http"      // HTTP istemci ve sunucu işlemleri için gerekli fonksiyonları sağlar
	"net/url"       // URL parse etme ve yapılandırma işlemleri yapar
	"os"            // dosya, kalsör ve işletim sistemi işlemlerini yönetir
	"path/filepath" // dosya yolları ile platform bağımsız çalışmayı sağlar
	"regexp"        // düzenli ifadelerle pattern eşleştirme yapar
	"strings"       // string manipülasyonları sağlar
	"time"          // zaman ve tarih işlemleri için

	"github.com/chromedp/chromedp" // GO ile Chrome tarayıcısını kontrol edip otomatik tarama ve ekran görüntüsü almaya yarar
	"golang.org/x/net/html"        // HTML parse etme ve DOM yapısı üzerinde gezinme imkanı sunar
	"golang.org/x/net/proxy"       // SOCKS5 veya HTTP proxy üzerinden bağlantı yapmayı sağlar, özellikler Tor gibi ağlar için kullanılır
)

const (
	torProxy9050   = "127.0.0.1:9050"
	torProxy9150   = "127.0.0.1:9150"
	requestTimeout = 30 * time.Second      // HTTP istekleri için bekleme süresini ayarlama
	outputHTMLDir  = "outputs/html"        // HTML çıktısını buraya kaydeder
	outputSSDir    = "outputs/screenshots" // Ekran görüntüsünü buraya kaydeder
	reportFile     = "scan_report.log"     // log dosyasını buraya kaydeder
	jsonReportFile = "outputs/report.json" // Site bilgilerini ve Tor ıp sini buraya kaydeder
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Report ana rapor yapısı
type Report struct {
	RunID      string      `json:"run_id"`         // Taramanın benzersiz kimliği
	StartedAt  string      `json:"started_at"`     // Taramanın başlangıç zamanı
	FinishedAt string      `json:"finished_at"`    // Taramanın bitiş zamanı
	TorInfo    *TorInfo    `json:"tor_connection"` // tor bağlantısı ile bilgiler
	Summary    *Summary    `json:"summary"`        // toplam, aktif ve pasif site sayısını içeren özet bilgiler
	Results    []*SiteData `json:"results"`        // her bir siteye ait detaylı tarama verilerini saklar
}

// TorInfo Tor bağlantı bilgileri
type TorInfo struct {
	Connected  bool   `json:"connected"`   // Tora başarıyla bağlanıp bağlanmadığını kontrol eder
	TorIP      string `json:"tor_ip"`      // Tor üzerinden görünen IP adresini
	ProxyUsed  string `json:"proxy_used"`  // kullanılan proxy adresini
	VerifiedAt string `json:"verified_at"` // bağlantının doğrulandığı zaman
	VerifyURL  string `json:"verify_url"`  // Tor bağlantısını test etmek için kullanılan doğrulama URL'sini içerir
}

// Summary özet bilgiler
type Summary struct {
	TotalURLs   int `json:"total_urls"`   // taranan toplam site sayısı
	ActiveURLs  int `json:"active_urls"`  // başarılı bir şekilde erişilebilen aktif site sayısı
	PassiveURLs int `json:"passive_urls"` // erişilemeyen veya hatalı site sayısını belirtir
}

// SiteData her site için toplanan veriler
type SiteData struct {
	URL            string `json:"url"`                        // Taranan sitenin adresi
	Status         string `json:"status"`                     // sitenin aktifmi pasifmi olduğunu
	StatusCode     int    `json:"status_code,omitempty"`      // HTTP yanıt kodunu
	Error          string `json:"error,omitempty"`            // oluşan hatayı
	ResponseTimeMs int64  `json:"response_time_ms,omitempty"` // isteğin yanıt süresini milisaniye cinsinden
	ScannedAt      string `json:"scanned_at"`                 // sitenin tarandığı zamanı gösterir

	Title         string `json:"title,omitempty"`            // sayfanın başlığı
	Description   string `json:"meta_description,omitempty"` // meta description içeriğini
	Server        string `json:"server,omitempty"`           // HTTP sunucu bilgisini
	ContentType   string `json:"content_type,omitempty"`     // içerik tipini
	ContentLength int64  `json:"content_length,omitempty"`   // içerik boyutunu byte cinsinden
	LastModified  string `json:"last_modified,omitempty"`    // sayfanın son değişiklik tarihini
	Powered       string `json:"x_powered_by,omitempty"`     // sayfanın hangi teknoloji veya platform ile çalıştığını gösterir

	// HTTP Headers
	Headers map[string]string `json:"headers,omitempty"`

	// Cookies
	Cookies []CookieData `json:"cookies,omitempty"`

	// Links
	Links *LinkData `json:"links,omitempty"`

	// Dosya bilgisi
	HTMLFile       string `json:"html_file,omitempty"`
	ScreenshotFile string `json:"screenshot_file,omitempty"`
}

// CookieData cookie bilgileri
type CookieData struct {
	Name     string `json:"name"`                // çerezin adını
	Value    string `json:"value"`               // değerini
	Domain   string `json:"domain,omitempty"`    // hangi alan adına ait olduğunu
	Path     string `json:"path,omitempty"`      // çerezin geçerli olduğu yolu
	HttpOnly bool   `json:"http_only,omitempty"` // çerezin sadece HTTP üzerinden erişilebilir olup olmadığını
	Secure   bool   `json:"secure,omitempty"`    // çerezin yalnızca HTTPS üzerinden gönderilip gönderilmeyeceğini belirtir
}

// LinkData sitedeki linkler
type LinkData struct {
	TotalCount    int        `json:"total_count"`    // sayfadaki toplam link sayısını
	InternalLinks []LinkInfo `json:"internal_links"` // aynı domain içindeki dahili linkleri
	ExternalLinks []LinkInfo `json:"external_links"` // farklı domainlere ait harici linkler
	OnionLinks    []LinkInfo `json:"onion_links"`    // .onion uzantılı Tor linklerini içerir.
}

// LinkInfo link detayları
type LinkInfo struct {
	URL  string `json:"url"`
	Text string `json:"text,omitempty"`
}

type TorClient struct {
	client    *http.Client // alanı Tor proxy’ye ayarlanmış http.Client nesnesini tutarak tüm isteklerin Tor üzerinden gitmesini sağla
	proxyAddr string       // kullanılan SOCKS5 Tor proxy adresini (örneğin 127.0.0.1:9050 veya 9150) saklayarak hangi proxy’nin aktif olduğunu takip etmeye yarar.
}

/*
Bu testTorConnection fonksiyonu, verilen proxy.Dialer üzerinden basit bir HTTP isteği
atarak Tor proxy’nin çalışıp çalışmadığını test eder; fonksiyon içinde yalnızca bu dialer’ı
kullanan kısa zaman aşımına (5 saniye) sahip bir http.Client oluşturulur,
http://example.com adresine GET isteği gönderilir ve istek hata almadan tamamlanırsa
Tor bağlantısının aktif olduğu kabul edilerek true, hata oluşursa false döndürülür.
*/
func testTorConnection(dialer proxy.Dialer) bool {
	testClient := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   5 * time.Second,
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err := testClient.Do(req)
	return err == nil
}

/*
Bu NewTorClient fonksiyonu, sistemde çalışan bir Tor SOCKS5 proxy’sini otomatik olarak
bulup ona bağlı bir HTTP istemcisi oluşturur; önce 9050 ve 9150 portlarını sırayla dener,
her port için bir SOCKS5 dialer oluşturur ve testTorConnection fonksiyonu ile bağlantının
gerçekten çalışıp çalışmadığını kontrol eder, çalışan bir proxy bulunamazsa hata döndürür,
başarılı olursa keep-alive kapalı ve Tor uyumlu bir http.Transport ile zaman aşımı
ayarlanmış bir http.Client üretir, yönlendirmeleri otomatik takip etmez ve en sonunda
aktif proxy adresini de içeren bir TorClient nesnesi döndürür.
*/
func NewTorClient() (*TorClient, error) {
	proxyAddrs := []string{torProxy9050, torProxy9150}
	var dialer proxy.Dialer
	var err error
	var workingProxy string

	for _, addr := range proxyAddrs {
		dialer, err = proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err == nil && testTorConnection(dialer) {
			workingProxy = addr
			break
		}
	}

	if workingProxy == "" {
		return nil, fmt.Errorf("Tor proxy bulunamadı (9050/9150 portları denendi)")
	}

	log.Printf("[INFO] Tor proxy bulundu: %s", workingProxy)

	transport := &http.Transport{
		Dial:               dialer.Dial,
		DisableKeepAlives:  true,
		DisableCompression: false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &TorClient{
		client:    client,
		proxyAddr: workingProxy,
	}, nil
}

/*
	Bu VerifyTor fonksiyonu, mevcut TorClient üzerinden gerçekten Tor ağına çıkılıp

çıkılmadığını doğrulamak için Tor Project’in resmi doğrulama API’sine istek gönderir;
fonksiyon önce kullanılan proxy adresi, doğrulama zamanı ve kontrol URL’si ile bir TorInfo
yapısı oluşturur, ardından check.torproject.org/api/ip adresine Tor üzerinden bir GET
isteği atar, dönen JSON yanıtını parse ederek bağlantının Tor olup olmadığını (IsTor) ve
görünen IP adresini alır, doğrulama başarısız olursa bağlantıyı pasif kabul eder, başarılı
olursa Tor’un aktif olduğunu loglar ve tüm bu bilgileri içeren TorInfo nesnesini geri döndürür.
*/
func (tc *TorClient) VerifyTor() *TorInfo {
	info := &TorInfo{
		Connected:  false,
		ProxyUsed:  tc.proxyAddr,
		VerifyURL:  "https://check.torproject.org/api/ip",
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}

	req, _ := http.NewRequest("GET", info.VerifyURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := tc.client.Do(req)
	if err != nil {
		log.Printf("[WARN] Tor doğrulama başarısız: %v", err)
		return info
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var torResp struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &torResp); err == nil {
		info.Connected = torResp.IsTor
		info.TorIP = torResp.IP
	}

	if info.Connected {
		log.Printf("[SUCCESS] Tor bağlantısı aktif! IP: %s", info.TorIP)
	}

	return info
}

// Target hedef site bilgisi
type Target struct {
	Name string // alanı kullanıcıya menüde veya loglarda gösterilecek hedefin kısa adını tutar
	URL  string // alanı ise Tor üzerinden tarama yapılacak web sitesinin tam adresini saklar.
}

/*
Bu readTargets fonksiyonu, verilen dosya adından hedef site listesini okuyup taramaya
uygun Target nesnelerine dönüştürür; fonksiyon dosyayı açar, satır satır okur, boş satırları
ve # ile başlayan yorum satırlarını atlar, her satırı “isim | URL” veya sadece “URL” formatına
göre ayrıştırır, geçerli http:// veya https:// ile başlayan adresleri Target listesine ekler,
dosya okuma sırasında hata oluşursa bunu döndürür, hiç geçerli hedef bulunamazsa hata
verir ve başarılı olduğunda taranacak tüm hedefleri içeren []Target dizisini geri döndürür.
*/
func readTargets(filename string) ([]Target, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("dosya açılamadı: %w", err)
	}
	defer file.Close()

	var targets []Target
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "|") {
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				url := strings.TrimSpace(parts[1])
				if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
					targets = append(targets, Target{Name: name, URL: url})
				}
			}
		} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			targets = append(targets, Target{Name: extractName(line), URL: line})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dosya okuma hatası: %w", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("geçerli URL bulunamadı")
	}

	return targets, nil
}

/*
Bu extractName fonksiyonu, verilen ham URL’den kullanıcıya gösterilecek kısa ve
okunabilir bir site adı üretir; fonksiyon URL’yi parse eder, host kısmını alır, .onion
uzantısını temizler, isim çok uzunsa 20 karakterle sınırlandırıp sonuna üç nokta ekler, URL
parse edilemezse "Unknown" döndürür ve bu sayede hedef siteler menüde veya loglarda
sade bir isimle gösterilir.
*/
func extractName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "Unknown"
	}
	host := strings.ReplaceAll(u.Host, ".onion", "")
	if len(host) > 20 {
		host = host[:20] + "..."
	}
	return host
}

/*
Bu showMenu fonksiyonu, okunmuş hedef siteleri kullanıcıya terminal üzerinden menü
şeklinde sunarak hangi sitelerin taranacağını seçmesini sağlar; fonksiyon tüm hedefleri
numaralandırarak ekrana yazdırır, kullanıcıdan giriş alır, q girilirse programı sonlandırır, 0
veya boş giriş yapılırsa tüm siteleri seçer, virgülle ayrılmış sayılar girilirse yalnızca seçilen
indekslerdeki siteleri yeni bir listeye ekler, geçersiz seçim yapılırsa varsayılan olarak tüm
siteleri döndürür ve sonuç olarak taramaya gönderilecek []Target listesini geri verir.
*/
func showMenu(targets []Target) []Target {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("                    TOR SCRAPER - HEDEF SEÇİMİ                ")
	fmt.Println("══════════════════════════════════════════════════════════════")

	for i, t := range targets {
		fmt.Printf("║  [%d] %-55s ║\n", i+1, t.Name)
	}

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  [0] Tüm siteleri tara                                       ")
	fmt.Println("  [q] Çıkış                                                   ")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("")
	fmt.Print("Seçiminiz (örn: 1,2,3 veya 0 hepsi için): ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "q" || input == "Q" {
		fmt.Println("Çıkış yapılıyor...")
		os.Exit(0)
	}

	if input == "0" || input == "" {
		fmt.Printf("\n[INFO] Tüm siteler (%d adet) taranacak.\n\n", len(targets))
		return targets
	}

	var selected []Target
	parts := strings.Split(input, ",")

	for _, p := range parts {
		p = strings.TrimSpace(p)
		var idx int
		if _, err := fmt.Sscanf(p, "%d", &idx); err == nil {
			if idx >= 1 && idx <= len(targets) {
				selected = append(selected, targets[idx-1])
			}
		}
	}

	if len(selected) == 0 {
		fmt.Println("[WARN] Geçersiz seçim, tüm siteler taranacak.")
		return targets
	}

	fmt.Printf("\n[INFO] %d site seçildi:\n", len(selected))
	for _, t := range selected {
		fmt.Printf("  - %s\n", t.Name)
	}
	fmt.Println("")

	return selected
}

// ============================================================================
// CRAWLER
// ============================================================================

func (tc *TorClient) Crawl(targetURL string) (*SiteData, []byte) {
	data := &SiteData{
		URL:       targetURL,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Headers:   make(map[string]string),
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		data.Status = "passive"
		data.Error = fmt.Sprintf("İstek oluşturulamadı: %v", err)
		return data, nil
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close")

	start := time.Now()
	resp, err := tc.client.Do(req)
	data.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		data.Status = "passive"
		data.Error = fmt.Sprintf("Bağlantı hatası: %v", err)
		return data, nil
	}
	defer resp.Body.Close()

	data.StatusCode = resp.StatusCode

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		data.Status = "active"
	} else {
		data.Status = "passive"
		data.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	data.Server = resp.Header.Get("Server")
	data.ContentType = resp.Header.Get("Content-Type")
	data.ContentLength = resp.ContentLength
	data.LastModified = resp.Header.Get("Last-Modified")
	data.Powered = resp.Header.Get("X-Powered-By")

	for key, values := range resp.Header {
		data.Headers[key] = strings.Join(values, ", ")
	}

	for _, cookie := range resp.Cookies() {
		data.Cookies = append(data.Cookies, CookieData{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
		})
	}

	var reader io.Reader = resp.Body
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gzReader.Close()
			reader = gzReader
		}
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		data.Error = fmt.Sprintf("İçerik okunamadı: %v", err)
		return data, nil
	}

	if strings.Contains(data.ContentType, "text/html") {
		parseHTMLContent(data, body, targetURL)
	}

	return data, body
}

/*
	Bu parseHTMLContent fonksiyonu, indirilen HTML içeriğini parse ederek sayfadan anlamlı

veriler çıkarmak için kullanılır; fonksiyon HTML’i DOM ağacına dönüştürür, sayfanın title
ve meta description bilgilerini alıp SiteData içine yazar, tüm <a> etiketlerini gezerek
linklerin URL ve görünen metinlerini çıkarır, linkleri dahili, harici ve .onion linkler olarak
sınıflandırır, toplam link sayısını hesaplar ve en sonunda elde edilen tüm link verilerini
SiteData yapısının Links alanına ekler.
*/
func parseHTMLContent(data *SiteData, body []byte, baseURL string) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	base, _ := url.Parse(baseURL)
	links := &LinkData{
		InternalLinks: []LinkInfo{},
		ExternalLinks: []LinkInfo{},
		OnionLinks:    []LinkInfo{},
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil {
					data.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "meta":
				name, content := "", ""
				for _, attr := range n.Attr {
					if attr.Key == "name" {
						name = strings.ToLower(attr.Val)
					}
					if attr.Key == "content" {
						content = attr.Val
					}
				}
				if name == "description" {
					data.Description = content
				}
			case "a":
				href := ""
				text := ""
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						href = attr.Val
					}
				}
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					text = strings.TrimSpace(n.FirstChild.Data)
					if len(text) > 100 {
						text = text[:100] + "..."
					}
				}
				if href != "" {
					linkInfo := processLink(href, text, base)
					if linkInfo != nil {
						links.TotalCount++
						categorizeLink(linkInfo, base, links)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			extract(child)
		}
	}

	extract(doc)
	data.Links = links
}

/*
	Bu processLink fonksiyonu, HTML içinden alınan bir linki temizleyip kullanılabilir hâle

getirir; fonksiyon boş, javascript:, mailto:, tel: veya sayfa içi (#) linkleri filtreleyerek
yok sayar, kalan linkleri URL olarak parse eder, göreceli (relative) adresleri sayfanın ana
URL’sine göre mutlak (absolute) adrese dönüştürür ve son olarak linkin tam adresi ile
görünen metnini içeren bir LinkInfo nesnesi döndürür.
*/
func processLink(href, text string, base *url.URL) *LinkInfo {

	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "#") {
		return nil
	}

	u, err := url.Parse(href)
	if err != nil {
		return nil
	}
	resolved := base.ResolveReference(u)

	return &LinkInfo{
		URL:  resolved.String(),
		Text: text,
	}
}

/*
	Bu categorizeLink fonksiyonu, verilen linki türüne göre sınıflandırır; fonksiyon linkin host

kısmını parse eder, .onion ile bitiyorsa OnionLinks listesine ekler, host boş veya base URL
ile aynıysa InternalLinks listesine ekler, aksi takdirde ExternalLinks listesine ekleyerek
sayfadaki linkleri dahili, harici ve .onion linkler olarak ayırır.
*/
func categorizeLink(link *LinkInfo, base *url.URL, links *LinkData) {
	u, err := url.Parse(link.URL)
	if err != nil {
		return
	}

	if strings.HasSuffix(u.Host, ".onion") {
		links.OnionLinks = append(links.OnionLinks, *link)
		return
	}

	if u.Host == "" || u.Host == base.Host {
		links.InternalLinks = append(links.InternalLinks, *link)
	} else {
		links.ExternalLinks = append(links.ExternalLinks, *link)
	}
}

/*
Bu takeScreenshot fonksiyonu, verilen URL’nin Tor ağı üzerinden ekran görüntüsünü alır
ve kaydeder. Fonksiyon önce screenshots klasörünü oluşturur, URL’den güvenli bir dosya
dı üretir ve ChromeDP kullanarak headless Chrome başlatır; Chrome, Tor SOCKS5 proxy
üzerinden çalışır ve DNS leak önleme gibi ayarlar içerir. Sayfa 8 saniye bekletilerek yüklenir,
ardından tam sayfa screenshot alınır ve .png formatında belirtilen klasöre kaydedilir.
Fonksiyon başarılı olursa dosya adını döner, hata oluşursa hata mesajı iletir.
*/
func takeScreenshot(torProxyAddr, hedefURL string) (string, error) {

	if err := os.MkdirAll(outputSSDir, 0755); err != nil {
		return "", fmt.Errorf("screenshots klasörü oluşturulamadı: %v", err)
	}

	dosyaAdi := safeFilename(hedefURL, ".png")
	dosyaYolu := filepath.Join(outputSSDir, dosyaAdi)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("proxy-server", fmt.Sprintf("socks5://%s", torProxyAddr)),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.UserAgent(userAgent),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(func(format string, v ...interface{}) {}),
		chromedp.WithErrorf(func(format string, v ...interface{}) {}),
	)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	log.Printf("[INFO] Tor proxy üzerinden screenshot alınıyor...")

	var screenshot []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(hedefURL),
		chromedp.Sleep(8*time.Second),
		chromedp.FullScreenshot(&screenshot, 90),
	)
	if err != nil {
		return "", fmt.Errorf("screenshot alınamadı: %v", err)
	}

	if err := os.WriteFile(dosyaYolu, screenshot, 0644); err != nil {
		return "", fmt.Errorf("screenshot kaydedilemedi: %v", err)
	}

	log.Printf("[INFO] Screenshot kaydedildi: %s", dosyaAdi)
	return dosyaAdi, nil
}

/*
	Bu safeFilename fonksiyonu, verilen URL’den dosya sistemi için güvenli ve çakışma

ihtimali düşük bir dosya adı üretir; fonksiyon URL’yi parse ederek host kısmını alır, .onion
uzantısını temizler, harf ve rakam dışındaki tüm karakterleri _ ile değiştirir, çok uzun
isimleri kısaltır, aynı domaine ait farklı URL’lerin çakışmasını önlemek için URL’nin SHA‑1
hash’inden kısa bir parça ekler ve en sonunda istenen dosya uzantısını ekleyerek
kullanılabilir bir dosya adı döndürür.
*/
func safeFilename(rawURL string, ext string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown" + ext
	}
	host := u.Host
	host = strings.ReplaceAll(host, ".onion", "")

	reg := regexp.MustCompile(`[^a-zA-Z0-9]`)
	host = reg.ReplaceAllString(host, "_")

	if len(host) > 40 {
		host = host[:40]
	}

	sum := sha1.Sum([]byte(rawURL))
	hash := hex.EncodeToString(sum[:])[:8]

	return fmt.Sprintf("%s_%s%s", host, hash, ext)
}

/*
Bu writeLogReport fonksiyonu, tarama sonuçlarını okunabilir bir metin formatında
scan_report.log dosyasına yazar. Fonksiyon önce dosyayı oluşturur, taramanın tarihini
kaydeder ve her site için durumu (ACTIVE veya PASSIVE), URL’yi, aktifse HTML dosya adı,
sayfa başlığı ve link istatistiklerini yazar; pasifse hata mesajını ekler. En sonunda tüm
taranan siteler için toplam, aktif ve pasif site sayısını içeren bir özet bölümü oluşturur. Bu
sayede kullanıcı, tarama sonuçlarını kolayca inceleyebilir.
*/
func writeLogReport(results []*SiteData) {
	file, err := os.Create(reportFile)
	if err != nil {
		log.Printf("[ERROR] Log dosyası oluşturulamadı: %v", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "=== TOR SCRAPER SCAN REPORT ===\n")
	fmt.Fprintf(file, "Tarih: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	activeCount := 0
	for _, r := range results {
		status := "PASSIVE"
		if r.Status == "active" {
			status = "ACTIVE"
			activeCount++
		}
		fmt.Fprintf(file, "[%s] %s\n", status, r.URL)
		if r.Status == "active" {
			fmt.Fprintf(file, "    -> HTML: %s\n", r.HTMLFile)
			fmt.Fprintf(file, "    -> Title: %s\n", r.Title)
			if r.Links != nil {
				fmt.Fprintf(file, "    -> Links: %d total (%d internal, %d external, %d onion)\n",
					r.Links.TotalCount, len(r.Links.InternalLinks), len(r.Links.ExternalLinks), len(r.Links.OnionLinks))
			}
		} else {
			fmt.Fprintf(file, "    -> Hata: %s\n", r.Error)
		}
		fmt.Fprintln(file)
	}

	fmt.Fprintf(file, "=== ÖZET ===\n")
	fmt.Fprintf(file, "Toplam: %d | Aktif: %d | Pasif: %d\n", len(results), activeCount, len(results)-activeCount)
}

/*
Bu writeJSONReport fonksiyonu, tarama sonuçlarını JSON formatında kaydeder. Fonksiyon
önce Report yapısını düzgün ve okunabilir bir şekilde (MarshalIndent) JSON’a
dönüştürür, ardından bunu outputs/report.json dosyasına yazar. Eğer JSON
oluşturulamaz veya dosyaya yazılamazsa hata mesajı verir. Başarılı olduğunda ise kaydın
tamamlandığını log’lar. Bu, tarama sonuçlarını programatik olarak işlemek veya başka
araçlarla analiz etmek için kullanışlıdır.
*/
func writeJSONReport(report *Report) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("[ERROR] JSON oluşturulamadı: %v", err)
		return
	}

	if err := os.WriteFile(jsonReportFile, data, 0644); err != nil {
		log.Printf("[ERROR] JSON dosyası yazılamadı: %v", err)
		return
	}

	log.Printf("[INFO] JSON rapor kaydedildi: %s", jsonReportFile)
}

/*
	main() fonksiyonu, TOR Scraper uygulamasının tüm tarama sürecini başlatan ana gövdeyi

oluşturur; öncelikle terminale taramanın başladığını bildirir ve ardından HTML çıktıları,
screenshot’lar ve genel raporlar için gerekli olan klasörleri (outputs/html,
outputs/screenshots, outputs) yoksa oluşturur; eğer herhangi bir klasör oluşturulamazsa
hata vererek programı sonlandırır. Daha sonra Report yapısını başlatarak her tarama
çalışması için benzersiz bir RunID ve taramanın başlangıç zamanını kaydeder ve boş bir
sonuç listesi (Results) ile hazırlar. Ardından NewTorClient() fonksiyonu ile Tor ağı
üzerinden istek gönderebilecek bir HTTP istemcisi oluşturur; eğer Tor çalışmıyorsa program
burada durur, aksi halde Tor modunun aktif olduğunu loglar. Bu istemci kullanılarak
VerifyTor() fonksiyonu çağrılır ve Tor bağlantısının aktif olup olmadığı, kullanılan proxy
adresi ve Tor IP bilgisi raporun TorInfo alanına kaydedilir. Daha sonra targets.yaml
dosyasından hedef URL’ler okunur ve geçerli URL’ler Target yapısı olarak listeye eklenir;
eğer dosya okunamaz veya geçerli URL yoksa program hata verir. Kullanıcıya showMenu()
fonksiyonu ile bir seçim menüsü sunularak tüm siteler veya seçili siteler taranmak üzere
belirlenir. Seçilen her URL için döngüye girilir; önce tc.Crawl() fonksiyonu ile site taranır
ve HTML içeriği ile SiteData bilgisi elde edilir. Eğer site aktifse, HTML çıktısı
safeFilename() ile güvenli bir dosya adıyla outputs/html klasörüne kaydedilir, ardından
takeScreenshot() fonksiyonu ile Tor proxy üzerinden sayfanın tam ekran görüntüsü alınır
ve outputs/screenshots klasörüne kaydedilir; her iki işlemde hata oluşursa loglar uyarı
verir. Tarama sonucunda site başlığı, toplam link sayısı ve diğer bilgileri loglanır; eğer site
pasifse hata mesajı loglanır. Tarama tamamlandığında, raporun FinishedAt zamanı
güncellenir ve Summary alanı oluşturularak toplam, aktif ve pasif site sayıları hesaplanır.
Son olarak writeLogReport() ile tarama sonucu log dosyası (scan_report.log) olarak
yazılır, writeJSONReport() ile tüm rapor JSON formatında (outputs/report.json)
kaydedilir. Program, tarama özetini kullanıcıya terminal üzerinden gösterir; toplam site
sayısı, aktif ve pasif site sayıları, HTML dosyalarının ve rapor dosyalarının yolları belirtilir. Bu
şekilde main() fonksiyonu, Tor üzerinden güvenli ve anonim şekilde web sitelerini
taramak, HTML ve screenshot çıktıları üretmek, linkleri analiz etmek ve kapsamlı bir rapor
oluşturmak için tüm süreçleri bir arada yürütür.
*/
func main() {
	log.Println("=== TOR Scraper Başlatılıyor ===")

	for _, dir := range []string{outputHTMLDir, outputSSDir, "outputs"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("[ERROR] Klasör oluşturulamadı: %v", err)
		}
	}

	report := &Report{
		RunID:     fmt.Sprintf("%d", time.Now().Unix()),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Results:   []*SiteData{},
	}

	tc, err := NewTorClient()
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	log.Println("[INFO] Tor modu aktif")

	report.TorInfo = tc.VerifyTor()

	allTargets, err := readTargets("targets.yaml")
	if err != nil {
		log.Fatalf("[ERROR] Hedef dosyası okunamadı: %v", err)
	}
	log.Printf("[INFO] %d adet hedef bulundu.", len(allTargets))

	selectedTargets := showMenu(allTargets)

	log.Printf("[INFO] Tarama başlatılıyor (%d site)...", len(selectedTargets))

	for i, target := range selectedTargets {
		log.Printf("[INFO] [%d/%d] Scanning: %s (%s)", i+1, len(selectedTargets), target.Name, target.URL)

		siteData, htmlBody := tc.Crawl(target.URL)

		if siteData.Status == "active" && htmlBody != nil {

			htmlFilename := safeFilename(target.URL, ".html")
			htmlPath := filepath.Join(outputHTMLDir, htmlFilename)

			if err := os.WriteFile(htmlPath, htmlBody, 0644); err != nil {
				log.Printf("[WARN] HTML kaydedilemedi: %v", err)
			} else {
				siteData.HTMLFile = htmlFilename
			}

			screenshotFile, ssErr := takeScreenshot(tc.proxyAddr, target.URL)
			if ssErr != nil {
				log.Printf("[WARN] Screenshot alınamadı: %v", ssErr)
			} else {
				siteData.ScreenshotFile = screenshotFile
			}

			log.Printf("[SUCCESS] %s -> Title: %s | Links: %d",
				target.Name, siteData.Title, siteData.Links.TotalCount)
		} else {
			log.Printf("[ERR] %s -> %s", target.Name, siteData.Error)
		}

		report.Results = append(report.Results, siteData)
	}

	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	activeCount := 0
	for _, r := range report.Results {
		if r.Status == "active" {
			activeCount++
		}
	}
	report.Summary = &Summary{
		TotalURLs:   len(selectedTargets),
		ActiveURLs:  activeCount,
		PassiveURLs: len(selectedTargets) - activeCount,
	}

	writeLogReport(report.Results)
	writeJSONReport(report)

	log.Println("")
	log.Println("=== Tarama Tamamlandı ===")
	log.Printf("[SUMMARY] Toplam: %d | Aktif: %d | Pasif: %d",
		report.Summary.TotalURLs, report.Summary.ActiveURLs, report.Summary.PassiveURLs)
	log.Printf("[INFO] HTML dosyaları: %s", outputHTMLDir)
	log.Printf("[INFO] Log rapor: %s", reportFile)
	log.Printf("[INFO] JSON rapor: %s", jsonReportFile)
}
