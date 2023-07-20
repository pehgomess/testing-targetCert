package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

func main() {
	http.HandleFunc("/checktargetserver", checkCertificateHandler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Erro ao iniciar o servidor:", err)
	}
}

func checkCertificateHandler(w http.ResponseWriter, r *http.Request) {
	site := r.URL.Query().Get("site")
	if site == "" {
		http.Error(w, "O parâmetro 'site' é obrigatório.", http.StatusBadRequest)
		return
	}

	portParam := r.URL.Query().Get("port")
	port := 443
	if portParam != "" {
		portInt, err := strconv.Atoi(portParam)
		if err != nil {
			http.Error(w, "Porta invalida", http.StatusBadRequest)
			return
		}
		port = portInt
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	timeout := 5 * time.Second
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", site+":"+strconv.Itoa(port), tlsConfig)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erro ao conectar ao site: %s", err), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if state.HandshakeComplete {
		http.Error(w, fmt.Sprintf("Handshake do certificado bem-sucedido.\n"), http.StatusOK)
		http.Error(w, fmt.Sprintf("-------------------------------------------------------------\n"), http.StatusOK)
	} else {
		fmt.Printf("Handshake do certificado falhou.\n")
	}

	verifyOptions := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         x509.NewCertPool(),
	}
	verifyOptions.Roots.AddCert(state.PeerCertificates[0])

	for _, v := range state.PeerCertificates {
		http.Error(w, fmt.Sprintf("Assunto: %s\n", v.Subject.CommonName), http.StatusOK)
		http.Error(w, fmt.Sprintf("Emitido por: %s\n", v.Issuer.CommonName), http.StatusOK)
		http.Error(w, fmt.Sprintf("Validade: %s - %s\n", v.NotBefore, v.NotAfter), http.StatusOK)
		http.Error(w, fmt.Sprintf("-------------------------------------------------------------\n"), http.StatusOK)
	}

	_, err = state.PeerCertificates[0].Verify(verifyOptions)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erro na verificação do certificado: %s\n", err), http.StatusUnauthorized)
	}
	statusCode := http.StatusMultiStatus
	if statusCode > 200 && statusCode <= 300 {
		http.Error(w, fmt.Sprintf("Conexao com o target OK, Status Code: %d\n", statusCode), statusCode)
	} else {
		fmt.Printf("Status Err, code: %d\n", statusCode)
	}

	expirationDate := state.PeerCertificates[0].NotAfter
	daysRemaining := int((expirationDate.Sub(time.Now()).Hours() / 24))

	switch {
	case daysRemaining <= 0:
		fmt.Printf("O certificado já expirou.: %s\n", expirationDate)
		http.Error(w, fmt.Sprintf("ERR: O certificado já expirou. %s\n", expirationDate), http.StatusUnauthorized)
	case daysRemaining <= 30:
		http.Error(w, fmt.Sprintf("WARNING: Faltam %d dias para a expiracao do certificado.\n", daysRemaining), http.StatusOK)
	default:
		http.Error(w, fmt.Sprintf("OK: Faltam mais de 30 dias, no caso %d dias para a expiração do certificado\n", daysRemaining), http.StatusOK)
	}
	w.WriteHeader(http.StatusOK)

}
