## zca

Basic certificate authority

#### Usage
```
python3 -m zca --help
Usage: __main__.py [OPTIONS] ORGANIZATION_NAME COMMAND [ARGS]...

  common cli work/variables

Options:
  --help  Show this message and exit.

Commands:
  generate_root_key               generate key for org ca root
  generate_root_cert              generate a new cert for the ca root
  generate_intermediary_key       generate key for org intermediary
  generate_intermediary_cert      generate a new cert for a ca intermediary
  generate_web_server_key         generate key for org server under...
  generate_web_server_cert        generate a new cert for org server under...
  generate_user_key               generate key for org user under intermediary
  generate_user_cert              generate cert for org user under
                                  intermediary
  generate_web_server_cert_chain
  generate_web_server_cert_chain_nginx
```
