FROM python:3.10

RUN apt-get update; \
    apt-get -y upgrade; \
    rm -fr /var/lib/apt/lists/*; \
    pip install --upgrade pip; \
    adduser --shell /usr/sbin/nologin --uid 10000 vmware-auditor; \
    chown vmware-auditor /home/vmware-auditor; \
    mkdir /app; \
    chown vmware-auditor /app;

USER vmware-auditor

WORKDIR /app

COPY . .

RUN python3 -m pip install -r requirements.txt

CMD [ "python3", "vcenter.py" ]