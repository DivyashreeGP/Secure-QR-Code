from feature_extractor import extract_features_from_url
import pandas as pd

# Column names based on your trained dataset
columns = [
    "url","length_url","length_hostname","ip","nb_dots","nb_hyphens","nb_at","nb_qm","nb_and","nb_or","nb_eq",
    "nb_underscore","nb_tilde","nb_percent","nb_slash","nb_star","nb_colon","nb_comma","nb_semicolumn","nb_dollar",
    "nb_space","nb_www","nb_com","nb_dslash","http_in_path","https_token","ratio_digits_url","ratio_digits_host",
    "punycode","port","tld_in_path","tld_in_subdomain","abnormal_subdomain","nb_subdomains","prefix_suffix",
    "random_domain","shortening_service","path_extension","nb_redirection","nb_external_redirection",
    "length_words_raw","char_repeat","shortest_words_raw","longest_words_raw","avg_words_raw","shortest_word_host",
    "longest_word_host","avg_word_host","shortest_word_path","longest_word_path","avg_word_path","phish_hints",
    "domain_in_brand","brand_in_subdomain","brand_in_path","suspecious_tld","statistical_report","nb_hyperlinks",
    "ratio_intHyperlinks","ratio_extHyperlinks","ratio_nullHyperlinks","nb_extCSS","ratio_intRedirection",
    "ratio_extRedirection","ratio_intErrors","ratio_extErrors","login_form","external_favicon","links_in_tags",
    "submit_email","ratio_intMedia","ratio_extMedia","sfh","iframe","popup_window","safe_anchor","onmouseover",
    "right_clic","empty_title","domain_in_title","domain_with_copyright","whois_registered_domain",
    "domain_registration_length","domain_age","web_traffic","dns_record","google_index","page_rank"
]

def extract_features_from_urls(url_list):
    feature_list = []
    for url in url_list:
        features = extract_features_from_url(url)
        features["url"] = url
        # Ensure all required keys are present
        complete_features = {col: features.get(col, 0) for col in columns}
        feature_list.append(complete_features)
    return pd.DataFrame(feature_list)

if __name__ == "__main__":
    urls = [
        "https://www.todayshomeowner.com/how-to-make-homemade-insecticidal-soap-for-plants/"
    ]

    df = extract_features_from_urls(urls)
    df.to_csv("features.csv", index=False)
    print("✅ Features extracted and saved to features.csv")
