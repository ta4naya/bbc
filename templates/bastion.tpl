#!/bin/bash

# add ssh keys to the `${ec2_user}` user

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCjILEJkuAz7qBJcM4ZhxvT8wcKFAAi4hO5UY55ZY9doI4MQ2D7WKVuYbQjsbTe8LoA+4IiFY2yFuuy6asRKPkwi87pa/tAE36YdAx2N6vNhjHZ1Y5cSvkzmzwokY+tZvLj1HB9Hst7Za6uDcnLhjgnCf9ExpPJ55nkYBltrdW6fnAMOZQ+Mu3CU+0jdQ/Vev/j1cJjwOQCqLeACZR8+vDZ3TWfrjLV5AqeBPQCvpe254cSy4+qDfGm9NyZqgEQ2nZCHkN3sIz61gByC45pDwcq4BIwu94VvhQLGGSCcRa2ZKPOcF++XSVscC5fBO/cmwbqxR4iEkI9pVywXvfWERiHGyVrcr0cvyO+SGFIi9XrqJEep9VWbGjP0jX9CnyDw3RSHL9f1r7UNrinO5bUeKon/ZKgtHdulfJS0FVupmezf5oSevONdfmBrHjQIYGW5OND8OZE4jG88u/UVOA8bCF1/pbExVralQbXaL8WEbhUKwmz3pVZVlxTn+HCLfLS8eJG7BsslhTte8sH5gpv7uN455gHZTb7Gjz9R9W+MHxDBUF7oUdsF5voaZWO9c0/WRzi4rM8IPakoLCfAHBgC2DQkVrNpJlmEcKjWAO2/WOL/7c5XcIyD+rbYH5z7euFO199FB9odZHhrLg99OZIRo67Jb/POM3pRIkcSCl9kio9oQ== timo.bumke@bayer.com" > /home/${ec2_user}/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDQ7sncYzGpXC6mAwo7PlTSdYk2jLi7kvcnR7+H+Z2pGrukaHOFlBMe5odsfRP3h0vLIVATqkgp5/Y35tHF5ZnPKwEZAzNBMo7uXXdGOzJ5mKW3h1xXHatGLGfsGiJ3BqNhOWuCkiuPfyyhhLDvJtijO+q93+ndnDn3IAMoiY77Ar9/KWQXDwRnEhfvuswAXwI69furMlcCZFlYC+34EdROEYeBXR2X1wlEaP8RxgY3kut68aBPrgKvqQvP6cqNRnYOZ8dqLBcRaGQlK2JhcIWLFeK1bFmTflqnt3RlryMJKCTLGxkkE3SVHdeiB/6G49zWQPWaGI0+08QrGbssPHevnSiYbpRb2eyN5yqBnDr3LXuSD7i/xpDMhKXa/2p3coS111/96yPwqTbQnO4dUqYdo5KJ98Munbt0C8alpn6TmjFXFA+0wEwXhBVbiYsQqwpKp0Q0ZqE3D+1YH7yIzQ4TkYHRvE8uRDtXWOz1b+ypzuTZNNC/HhBE3VIXOX5XfKriAdiZFEOIlFHG052Oslk7WXRPBOWygkE6VSek/caWhWt94nfkFN5B/+WBk5Hkv6hMH/BITATpLt6uPByHKX/dH0yCTD+SOoKbeQ7k8l0C+orWMdi+Fcnqz0DPgiYGFsG60o14cJD3VeMP/At+EZ1HAjfyUi+k/dO06RfczAV1mw== kelechi.igbokwe@bayer.com" >> /home/${ec2_user}/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC3MGQxJDlJzN9DUfL9Jlo7k+2w8+7D6CIshgjAe/rzb3ahsktjAnbrmlt/A9az4pM5gn8m54PoF+puMiJc/RSqpl9KNDbnbCEI07jBcda1p+3v1rX5ZhZx2ao4fxlHrYFuu/gJPgICafcl0b7cRz4x37iIxFJWo8LlZedudpRyZjreHe4PsFVUzsltvcjHl7ODmovTGCvnRX6iUpFqTSQz+15mHO0/p4VQNTkjhGivHH1VNLxJqg2WV5fwgWflAkEh2XMIWgeC+oOfS5Usfqd029IA+3HJmk9w28U1GWLqZ6mLeLh0nYIr4pzYlX10fVPe7v6gKuNSDmS4bAXYH85NGpyl6ACeC/0Md29L+MQiK/7Jt5j/x3MVxs4dDqyq7K+Qk1cJuSJBARHxDvtBNQkznNjQVRgGoAIv72mUiQLqLPZS9XZdKeyIDhXgq04WS+Tqe/6fCHRpuVXIdrCj3hQsDUBKNm5cPWEpwQ0OL8w2FdVeuAGkRtN8ZR20Vv1rV8appM3CCwZ7reDOIihQAneNAS7s1ozqo8mWKxW4hIqnXDx7QeEDm5caDvCSXnW9L1nGEx90U5FdTc3IA8XlYIMXSBilibTY/JkIFxCdVq1Ar3cViStowmX4bL16yfBxXjAR3Rb/oBEZIAS7qBdiTIkJTcvJcWuMafNNAE/p+VMYtQ== thomas.widhalm.ext@bayer.com" >> /home/${ec2_user}/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCWk51sI3vR/d8lyzBF1uQ517wnxn4x2NotUOrCoOxaS1XeiIozfOc+PP7G9fTamjzmYGP5fztnKozt4cCfu+jIw1M5Ghu26zoC1LhnfDU6kGqwBao+/8BxxEcz51bkP2NDavt7dx30l6GtpGJD2IJewGcnEPUQBiGKW/gnMbEgePJhvw2BNY6HJt6i+0rUom4kvnaXFujwCboJXlntMeEtRaE3IUUpxm4/UtJcXSOOep3bJscxD/RGuUNXI4TsSZ/L3R3QOVRQyoVUeyZRSg/zR0JkBy4k/uhOzUQOZwzG6JjzxK9k+lnzyMf5QHYPDvoxhL0LbivkwBiumhXgEVvycXgg/mSI1yWfOM/3d79Zjl5TrpFY5fjPHkxdjaHKjf1jTmoPnYvujur3FWdRt2rFZQL39KCPbYXNQX3HCPZRmNeFPhE+6zm/PoER0KwvXpmg0xiAUq11VqjLpENRdpAvKKIsMxy14f2PgVH2sWCn+6EIMZ/4FL4toMhEMmIefB2HqLXHYghpaK1Ogwmg1rUCjKDgXhv+zidhki0wlB/XGwIjIKiuQUalmRjXG37fNvAR7S6acsTZ2XGYYN2P8c2+wmrCOmahuHi6ewDW27FFYlgpYnXNJxVAR4OfgxL2o4RhuRKJY7kQertoy64/y6VGaBc/LPwAnIEgqYg/ii47WQ== afeef.ghannam.ext@bayer.com" >> /home/${ec2_user}/.ssh/authorized_keys
chown ${ec2_user}: /home/${ec2_user}/.ssh/authorized_keys
chmod 0600 /home/${ec2_user}/.ssh/authorized_keys

# install additional files from archive

yum -y install deltarpm awscli
yum update -y
if [ -n "${files}" ]; then
    pushd /
    aws s3 cp s3://${bucket_name}/${bucket_path}/${files} .
    tar -xzf ${files}
    popd
fi

# change default port in sshd_config

if [ ${sshd_port} -ne 22 ]; then
    semanage port -a -t ssh_port_t -p tcp ${sshd_port}
    sed -ri "s/^#?Port 22$/Port ${sshd_port}/" /etc/ssh/sshd_config
    systemctl restart ${sshd_svcname}.service
fi
