# Tricks with Trojan's v1.0 - İnteraktif Güvenlik Aracı

![Lisans](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Versiyon](https://img.shields.io/badge/version-1.0-brightgreen.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)

**Tricks with Trojan's (TWT)**, Windows sistemler için geliştirilmiş, PowerShell tabanlı, interaktif bir sistem analizi ve temel tehdit müdahale aracıdır. Kullanıcı dostu metin menüsü sayesinde, hem yeni başlayanlar hem de deneyimli kullanıcılar için sistemlerinde hızlıca güvenlik kontrolleri yapma imkanı sunar.

*Oluşturan (Created by): Emircan Akalın*

---

### Ekran Görüntüsü / Screenshot
*(Buraya konsol menüsünün bir ekran görüntüsünü ekleyebilirsiniz. Yükledikten sonra aşağıdaki URL'yi değiştirin.)*
*(You can add a screenshot of the console menu here. Replace the URL below after uploading.)*

![Tricks with Trojan's Menü](https://user-images.githubusercontent.com/username/repo/path/to/screenshot.png) 
*Ana menünün görünümü (View of the main menu)*

---

## 🚀 Özellikler (Features)

* **İnteraktif Metin Menüsü:** Tüm modüllere kolay erişim sağlayan kullanıcı dostu bir arayüz.
* **HTML Raporlama:** Tüm analiz sonuçlarını tek bir düzenli HTML dosyasında toplar.
* **Güvenli Karantina:** Şüpheli dosyaları kalıcı olarak silmek yerine, geri döndürülebilir şekilde karantinaya alır.
* **Otomatik Yedekleme:** Başlangıç öğelerini silmeden önce kayıt defteri (registry) anahtarlarını otomatik olarak yedekler.
* **Kapsamlı Analiz Modülleri:**
    * Geçici dosya temizliği.
    * Seçenekli (Hızlı/Tam) Windows Defender taraması.
    * Başlangıçta çalışan programların analizi ve kaldırılması.
    * Aktif ağ bağlantılarının listelenmesi ve ilgili işlemlerin sonlandırılması.
    * `hosts` dosyası analizi ile zararlı yönlendirmelerin tespiti.
    * Windows Olay Günlükleri'nde şüpheli aktivitelerin taranması.
    * Kullanıcı klasörlerinde yeni oluşturulmuş şüpheli dosyaların tespiti.

---

## 🛠️ Gereksinimler (Prerequisites)

* **İşletim Sistemi:** Windows 10 veya üstü
* **PowerShell:** Versiyon 5.1 veya üstü
* **Yetki:** Script'in tam işlevsellikle çalışabilmesi için **Yönetici (Administrator)** olarak çalıştırılması zorunludur.

---

## ⚙️ Kurulum ve Kullanım (Installation and Usage)

1.  **Script'i İndirin:** Bu repodan `Tricks-With-Trojans.ps1` (veya belirlediğiniz `.ps1` uzantılı) dosyasını indirin.
2.  **PowerShell'i Yönetici Olarak Açın:**
    * Başlat menüsüne "PowerShell" yazın.
    * "Windows PowerShell"e sağ tıklayın ve **"Yönetici olarak çalıştır" (Run as administrator)** seçeneğini seçin.
3.  **Script Dizinine Gidin:**
    * Konsolda, dosyayı indirdiğiniz klasörün yoluna gidin. Örnek:
    ```powershell
    cd C:\Users\Emircan\Downloads
    ```
4.  **Execution Policy Ayarı (Gerekirse):**
    * Eğer script'i çalıştırırken bir hata alırsanız, PowerShell'in script çalıştırma politikasını değiştirmeniz gerekebilir. Aşağıdaki komutu çalıştırarak sadece mevcut oturum için izin verin:
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope Process
    ```
5.  **Script'i Çalıştırın:**
    ```powershell
    .\Tricks-With-Trojans.ps1
    ```
6.  Karşınıza çıkan menüden istediğiniz işlemi seçerek aracı kullanmaya başlayın.

---

## 📖 Modüllerin Açıklaması (Modules Explained)

* **1. Geçici Dosyaları Temizle:** Windows ve kullanıcı TEMP klasörlerindeki gereksiz dosyaları siler.
* **2. Windows Defender Taraması Başlat:** Hızlı veya Tam tarama seçenekleri sunarak sistemi tarar.
* **3. Dosyayı Karantinaya Al:** Belirtilen bir dosyayı güvenli karantina klasörüne taşır.
* **4. Başlangıç Öğelerini Analiz Et:** Kayıt defteri ve başlangıç klasörlerini tarar, şüpheli öğeleri kaldırma seçeneği sunar.
* **5. Aktif Ağ Bağlantılarını Göster:** `ESTABLISHED` durumundaki bağlantıları ve bu bağlantıları kuran işlemleri listeler, işlem sonlandırma imkanı tanır.
* **6. Hosts Dosyasını Kontrol Et:** `hosts` dosyasındaki standart dışı kayıtları bularak raporlar.
* **7. Şüpheli Olay Günlüklerini Tara:** Yeni servis kurulumları, çok sayıda başarısız giriş gibi olayları kontrol eder.
* **8. Yeni Oluşturulmuş Şüpheli Dosyaları Bul:** Kritik kullanıcı klasörlerinde son 7 günde oluşturulmuş programları listeler.
* **9. TÜM ANALİZLERİ ÇALIŞTIR:** Tüm analiz modüllerini (4-8) sırayla çalıştırır ve Masaüstü'ne detaylı bir HTML raporu oluşturur.

---

## 📜 Lisans (License)

Bu proje **[GNU General Public License v3.0](LICENSE)** altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına göz atın.

---

## 🤝 Katkıda Bulunma (Contributing)

Katkıda bulunmak isterseniz, lütfen bir "issue" açarak önerilerinizi belirtin veya bir "pull request" oluşturun. Tüm katkılar memnuniyetle karşılanır!

1.  Projeyi Fork'layın.
2.  Yeni bir Feature Branch oluşturun (`git checkout -b feature/AmazingFeature`).
3.  Değişikliklerinizi Commit'leyin (`git commit -m 'Add some AmazingFeature'`).
4.  Branch'inizi Push'layın (`git push origin feature/AmazingFeature`).
5.  Bir Pull Request açın.
