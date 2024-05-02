python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

echo "Setup complete."
echo "Run 'source .venv/bin/activate' to activate the virtual environment with the required packages: "
cat requirements.txt
echo "Then run 'python3 extractpdfs.py -P <password> <file1> <fil2> ...' to generate the index." 