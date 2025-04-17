import os
import time
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from urllib.parse import urlparse


filtered_urls = ['https://www.us-cert.gov/ics/advisories/ICSA-10-238-01B',
 'https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html',
 'https://www.carbonblack.com/2019/03/22/tau-threat-intelligence-notification-lockergoga-ransomware/',
 'https://www.trendmicro.com/en_us/research/18/a/new-killdisk-variant-hits-financial-organizations-in-latin-america.html',
 'https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf',
 'https://www.crysys.hu/publications/files/skywiper.pdf',
 'https://www.secureworks.com/research/wcry-ransomware-analysis',
 'https://www.us-cert.gov/ncas/alerts/TA17-132A',
 'https://news.softpedia.com/news/on-chernobyl-s-30th-anniversary-malware-shuts-down-german-nuclear-power-plant-503429.shtml',
 'https://www.symantec.com/security-center/writeup/2010-071400-3123-99',
 'https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html',
 'https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html',
 'https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html',
 'https://www.bleepingcomputer.com/news/security/killdisk-disk-wiping-malware-adds-ransomware-component/',
 'https://www.esetnod32.ru/company/viruslab/analytics/doc/Stuxnet_Under_the_Microscope.pdf',
 'https://www.youtube.com/watch?v=XwSJ8hloGvY',
 'https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/',
 'https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/',
 'https://download.schneider-electric.com/files?p_Doc_Ref=SESB-2022-01',
 'https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=7382dce7-0260-4782-84cc-890971ed3f17&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments',
 'https://www.dragos.com/wp-content/uploads/CrashOverride-01.pdf',
 'https://dragos.com/wp-content/uploads/CRASHOVERRIDE.pdf',
 'https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf',
 'https://download.schneider-electric.com/files?p_enDocType=Technical+leaflet&p_File_Name=SEVD-2017-347-01+Triconex+V3.pdf&p_Doc_Ref=SEVD-2017-347-01',
 'https://ics-cert.us-cert.gov/sites/default/files/documents/MAR-17-352-01%20HatMan%20-%20Safety%20System%20Targeted%20Malware%20%28Update%20B%29.pdf',
 'http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/',
 'https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/',
 'https://hub.dragos.com/hubfs/116-Whitepapers/Dragos_ChernoviteWP_v2b.pdf?hsLang=en',
 'https://claroty.com/team82/research/unpacking-the-blackjack-groups-fuxnet-malware',
 'https://www.gdatasoftware.com/blog/2019/06/31724-strange-bits-sodinokibi-spam-cinarat-and-fake-g-data',
 'https://www.cisa.gov/uscert/ncas/alerts/aa22-103a',
 'https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Jimmy%20Wylie%20-%20Analyzing%20PIPEDREAM%20Challenges%20in%20testing%20an%20ICS%20attack%20toolkit.pdf',
 'https://intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation/',
 'https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html',
 'https://www.tetradefense.com/incident-response-services/cause-and-effect-sodinokibi-ransomware-analysis',
 'https://www.blackhat.com/docs/asia-16/materials/asia-16-Spenneberg-PLC-Blaster-A-Worm-Living-Solely-In-The-PLC.pdf',
 'https://scadahacker.com/resources/stuxnet-mitigation.html',
 'https://unit42.paloaltonetworks.com/threat-assessment-ekans-ransomware/',
 'https://www.symantec.com/connect/blogs/flamer-recipe-bluetoothache',
 'https://collaborate.mitre.org/attackics/index.php/Software/S0001',
 'https://dragos.com/blog/trisis/TRISIS-01.pdf',
 'https://www.langner.com/wp-content/uploads/2017/03/to-kill-a-centrifuge.pdf',
 'https://www.welivesecurity.com/wp-content/uploads/200x/white-papers/ESET_ACAD_Medre_A_whitepaper.pdf',
 'https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/',
 'https://www.secureworks.com/research/revil-sodinokibi-ransomware',
 'https://blog.talosintelligence.com/2018/06/vpnfilter-update.html',
 'https://securelist.com/bad-rabbit-ransomware/82851/',
 'https://blog.talosintelligence.com/2019/04/sodinokibi-ransomware-exploits-weblogic.html',
 'https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/',
 'https://threatvector.cylance.com/en_us/home/threat-spotlight-sodinokibi-ransomware.html',
 'https://www.wired.com/images_blogs/threatlevel/2011/02/Symantec-Stuxnet-Update-Feb-2011.pdf',
 'https://www.youtube.com/watch?v=f09E75bWvkk&index=3&list=PL8OWO1qWXF4qYG19p7An4Vw3N2YZ86aRS&t=0s',
 'https://vblocalhost.com/uploads/VB2021-Slowik.pdf',
 'https://us-cert.cisa.gov/ncas/alerts/TA17-163A',
 'https://www.dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/',
 'https://www.youtube.com/watch?v=yuZazP22rpI',
 'https://www.midnightbluelabs.com/blog/2018/1/16/analyzing-the-triton-industrial-malware',
 'https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/',
 'https://www.secureworks.com/blog/revil-the-gandcrab-connection',
 'https://www.youtube.com/watch?v=xC9iM5wVedQ',
 'https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers',
 'https://www.mandiant.com/resources/incontroller-state-sponsored-ics-tool',
 'https://securelist.com/sodin-ransomware/91473/',
 'https://www.justice.gov/opa/press-release/file/1328521/download',
 'https://www.group-ib.com/whitepapers/ransomware-uncovered.html',
 'https://www.trendmicro.com/en_us/research/18/f/new-killdisk-variant-hits-latin-american-financial-organizations-again.html',
 'https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter',
 'https://www.dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/',
 'https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/w32_duqu_the_precursor_to_the_next_stuxnet.pdf',
 'https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf',
 'https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/',
 'https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-crescendo/',
 'https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf',
 'https://www.blackhat.com/docs/asia-16/materials/asia-16-Spenneberg-PLC-Blaster-A-Worm-Living-Solely-In-The-PLC-wp.pdf',
 'https://www.us-cert.gov/ncas/alerts/TA17-181A',
 'https://www.washingtonpost.com/business/economy/more-than-150-countries-affected-by-massive-cyberattack-europol-says/2017/05/14/5091465e-3899-11e7-9e48-c4f199710b69_story.html?utm_term=.7fa16b41cad4',
 'https://web.archive.org/web/20200125132645/https://www.sans.org/security-resources/malwarefaq/conficker-worm',
 'https://us-cert.cisa.gov/ics/advisories/ICSA-10-272-01',
 'https://www.fireeye.com/blog/threat-research/2020/02/ransomware-against-machine-learning-to-disrupt-industrial-production.html',
 'https://dragos.com/blog/crashoverride/CrashOverride-01.pdf',
 'https://www.picussecurity.com/blog/a-brief-history-and-further-technical-analysis-of-sodinokibi-ransomware',
 'https://collaborate.mitre.org/attackics/index.php/Software/S0010',
 'https://securelist.com/the-flame-questions-and-answers-51/34344/']


# Folder to save PDFs
output_dir = "/Users/nettayaakobi/Desktop/Final_project_codes/FinalProject-DataScience/CTI_reports_extraction/reports_proc_description"
os.makedirs(output_dir, exist_ok=True)

# Configure Chrome options
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
chrome_options.add_argument('--kiosk-printing')

# Setup Chrome PDF printer settings
app_state = {
    "recentDestinations": [{"id": "Save as PDF", "origin": "local", "account": ""}],
    "selectedDestinationId": "Save as PDF",
    "version": 2
}

prefs = {
    'printing.print_preview_sticky_settings.appState': str(app_state),
    'savefile.default_directory': output_dir
}
chrome_options.add_experimental_option('prefs', prefs)
chrome_options.add_argument('--kiosk-printing')

# Start driver
driver_path = "/opt/homebrew/bin/chromedriver"  # Adjust if different
service = Service(driver_path)
driver = webdriver.Chrome(service=service, options=chrome_options)

log = []

for i, url in enumerate(filtered_urls):
    try:
        driver.get(url)
        time.sleep(5)  # Wait for full page load
        filename = f"report_{i+1}.pdf"
        filepath = os.path.join(output_dir, filename)

        # Save PDF using DevTools command
        result = driver.execute_cdp_cmd("Page.printToPDF", {"printBackground": True})
        with open(filepath, "wb") as f:
            f.write(bytes.fromhex(result['data']))

        log.append({"url": url, "status": "Saved as PDF", "filename": filename})
        print(f"✅ Saved {filename}")
    except Exception as e:
        log.append({"url": url, "status": f"Error - {e}"})

driver.quit()

# Save download log
log_df = pd.DataFrame(log)
log_df.to_csv(os.path.join(output_dir, "selenium_pdf_log.csv"), index=False)
print("✅ All done. Log saved.")
