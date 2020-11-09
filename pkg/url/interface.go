package url

import (
	"fmt"
	"github.com/openshift/odo/pkg/component"
	componentlabels "github.com/openshift/odo/pkg/component/labels"
	"github.com/openshift/odo/pkg/envinfo"
	"github.com/openshift/odo/pkg/kclient"
	urlLabels "github.com/openshift/odo/pkg/url/labels"
	"github.com/pkg/errors"
	iextensionsv1 "k8s.io/api/extensions/v1beta1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"
	"strings"
)

type comp interface {
	GetURLs() map[string]url
	Push() error
	GetName() string
	GetApplication() string
	AddUrl(infoURL *envinfo.EnvInfoURL) url
}

type devfileComp struct {
	urls       map[string]url
	secretName string
}

func (comp *devfileComp) getOwnerRef() v1.OwnerReference {
	panic("implement me")
}
func (comp *devfileComp) getLabels() map[string]string {
	// compute a new copy of the component's labels
	panic("implement me")
}

func (comp *devfileComp) GetURLs() map[string]url {
	return comp.urls
}

func (comp *devfileComp) GetName() string {
	panic("implement me")
}

func (comp *devfileComp) GetApplication() string {
	panic("implement me")
}

func (comp *devfileComp) AddUrl(infoURL *envinfo.EnvInfoURL) url {
	switch infoURL.Kind {
	case envinfo.INGRESS:
		return newNonPushedIngress(infoURL, comp)
	}
	return nil
}

func (comp *devfileComp) Push() error {
	// push/create the component representation if needed
	// ...

	// push URLs if needed
	for _, url := range comp.GetURLs() {
		switch s := url.GetStatus().State; s {
		case StateTypeLocallyDeleted:
			url.Delete()
		case StateTypeNotPushed:
		case StateTypeUnknown:
		case StateTypePushed:
			url.CreateOrUpdate()
		default:
			return fmt.Errorf("unknown url state '%s'", s)
		}
	}

	// ...
	return nil
}

type devfileURL struct {
	parent *devfileComp
	name   string
}

func (u *devfileURL) getOwnerRef() v1.OwnerReference {
	return u.parent.getOwnerRef()
}

func (u *devfileURL) getLabels() map[string]string {
	labels := u.parent.getLabels()
	labels[urlLabels.URLLabel] = u.name
	return labels
}

func (u *devfileURL) getSecretLabels() map[string]string {
	return u.parent.getLabels()
}

func (u *devfileURL) setSecret(secret string) {
	panic("implement me")
}

type url interface {
	CreateOrUpdate() error
	Delete() error
	GetName() string
	GetHost() string
	GetProtocol() string
	GetPort() int
	IsSecure() bool
	GetKind() envinfo.URLKind
	GetTLSSecret() string
	GetPath() string
	GetStatus() URLStatus
	GetParent() comp
}

func Coalescing(a, b interface{}) interface{} {
	if a != nil {
		return a
	} else if b != nil {
		return b
	}
	return nil
}

func NewPushedURL(data interface{}, localState envinfo.EnvInfoURL) url {
	if value, ok := data.(iextensionsv1.Ingress); ok {
		return ingressURL{
			localState: &localState,
			ingress:    &value,
		}
	}
	return nil
}

type ingressURL struct {
	*devfileURL
	localState *envinfo.EnvInfoURL
}

func (i ingressURL) GetParent() comp {
	panic("implement me")
}

func (i ingressURL) Delete() error {
	client, err := kclient.GetInstance()
	if err != nil {
		return err
	}
	return client.DeleteIngress(i.localState.Name)
}

func newNonPushedIngress(localState *envinfo.EnvInfoURL, parent *devfileComp) url {
	return ingressURL{
		devfileURL: &devfileURL{
			parent: parent,
			name:   localState.Name, // this needs to be cleaned up
		},
		localState: localState,
	}
}

func NewIngress(ingress *iextensionsv1.Ingress, localState *envinfo.EnvInfoURL) url {
	return ingressURL{
		ingress:    ingress,
		localState: localState,
	}
}

func (i ingressURL) CreateOrUpdate() error {
	client, err := kclient.GetInstance()
	if err != nil {
		return err
	}

	serviceName := i.GetName()

	if i.localState.Host == "" {
		return errors.Errorf("the host cannot be empty")
	}
	ingressDomain := fmt.Sprintf("%v.%v", i.localState.Name, i.localState.Host)

	ownerReference := i.getOwnerRef()
	if i.IsSecure() {
		secret := i.GetTLSSecret()
		if len(secret) == 0 {
			defaultTLSSecretName := serviceName + "-tlssecret"
			_, err := client.KubeClient.CoreV1().Secrets(client.Namespace).Get(defaultTLSSecretName, metav1.GetOptions{})
			// create tls secret if it does not exist
			if kerrors.IsNotFound(err) {
				selfsignedcert, err := kclient.GenerateSelfSignedCertificate(i.GetHost())
				if err != nil {
					return errors.Wrap(err, "unable to generate self-signed certificate for clutser: "+i.localState.Host)
				}
				// create tls secret
				objectMeta := metav1.ObjectMeta{
					Name:   defaultTLSSecretName,
					Labels: i.getSecretLabels(),
					OwnerReferences: []v1.OwnerReference{
						ownerReference,
					},
				}
				if _, err := client.CreateTLSSecret(selfsignedcert.CertPem, selfsignedcert.KeyPem, objectMeta); err != nil {
					return errors.Wrap(err, "unable to create tls secret "+defaultTLSSecretName)
				}
			} else if err != nil {
				return err
			}
			i.setSecret(defaultTLSSecretName)
		} else {
			// maybe we should assume at this point that the secret exists, since it should have been validated before?
			_, err := client.KubeClient.CoreV1().Secrets(client.Namespace).Get(secret, metav1.GetOptions{})
			if err != nil {
				return errors.Wrap(err, "unable to get the provided secret: "+secret)
			}
		}

	}
	ingressParam := kclient.IngressParameter{ServiceName: serviceName, IngressDomain: ingressDomain, PortNumber: intstr.FromInt(i.localState.Port), TLSSecretName: i.localState.TLSSecret, Path: i.localState.Path}
	ingressSpec := kclient.GenerateIngressSpec(ingressParam)
	objectMeta := kclient.CreateObjectMeta(serviceName, client.Namespace, i.getLabels(), nil)
	// to avoid error due to duplicate ingress name defined in different devfile components
	objectMeta.Name = fmt.Sprintf("%s-%s", i.GetName(), serviceName)
	objectMeta.OwnerReferences = append(objectMeta.OwnerReferences, ownerReference)
	// Pass in the namespace name, link to the service (componentName) and labels to create a ingress
	_, err = client.CreateIngress(objectMeta, *ingressSpec)
	if err != nil {
		return errors.Wrap(err, "unable to create ingress")
	}
	//return GetURLString(GetProtocol(routev1.Route{}, *ingress), "", ingressDomain, false), nil
	return nil
}

func (i ingressURL) GetName() string {
	return Coalescing(i.ingress.Name, i.localState.Name).(string)
}

func (i ingressURL) GetHost() string {
	return strings.Replace(i.ingress.Spec.Rules[0].Host, i.GetName()+".", "", 1)
}

func (i ingressURL) GetProtocol() string {
	if i.ingress.Spec.TLS != nil {
		return "https"
	}
	return "https"
}

func (i ingressURL) GetPort() int {
	return i.ingress.Spec.Rules[0].HTTP.Paths[0].Backend.ServicePort.IntValue()
}

func (i ingressURL) IsSecure() bool {
	return i.ingress.Spec.TLS != nil
}

func (i ingressURL) GetKind() URLKind {
	return INGRESS
}

func (i ingressURL) GetTLSSecret() string {
	return i.ingress.Spec.TLS[0].SecretName
}

func (i ingressURL) GetPath() string {
	return i.ingress.Spec.Rules[0].HTTP.Paths[0].Path
}

func (i ingressURL) GetStatus() URLStatus {
	var urlStatus URLStatus
	if i.localState == nil {
		urlStatus = URLStatus{
			State: StateTypeNotPushed,
		}
	}
	if i.ingress != nil {
		if urlStatus.State == StateTypeLocallyDeleted {
			urlStatus = URLStatus{
				State: StateTypeLocallyDeleted,
			}
		} else {
			urlStatus = URLStatus{
				State: StateTypePushed,
			}
		}
	} else {
		urlStatus = URLStatus{
			State: StateTypeUnknown,
		}
	}
	return urlStatus
}

///////////////////////

type urlClient interface {
	Create(url envinfo.EnvInfoURL, component component.OdoComponent) error
	Delete(url url) error
	List() ([]url, error)
	ListPushed() ([]url, error)
}

type kubernetesClient struct {
	kClient   kclient.Client
	env       envinfo.LocalConfigProvider
	component component.OdoComponent
}

func NewClient() urlClient {
	// TODO use context to determine type of client
	return kubernetesClient{
		// get the kClient from the context or create one
	}
}

func (k kubernetesClient) ListPushed() ([]url, error) {
	labelSelector := fmt.Sprintf("%v=%v", componentlabels.ComponentLabel, k.component.GetName())
	klog.V(4).Infof("Listing ingresses with label selector: %v", labelSelector)
	ingresses, err := k.kClient.ListIngresses(labelSelector)
	if err != nil {
		return []url{}, errors.Wrap(err, "unable to list ingress names")
	}

	var urls []url
	for _, ingress := range ingresses {
		for _, localURL := range k.env.GetURL() {
			if localURL.Name == ingress.Name {
				urls = append(urls, NewIngress(&ingress, &localURL))
			}
		}
	}
	return urls, nil
}

func (k kubernetesClient) List() ([]url, error) {
	remoteUrls, _ := k.ListPushed()

	if _, ok := k.component.(component.KubernetesComponent); !ok {
		return []url{}, nil
	}

	var urls []url
	for _, localURL := range k.env.GetURL() {
		found := false
		for _, remoteUrls := range remoteUrls {
			found = true
			if remoteUrls.GetName() == localURL.Name {
				if remoteUrls.GetStatus().State == StateTypePushed {
					found = true
				}
			}
		}
		if !found {
			url := NewNonPushedIngress(&localURL, k.component.(component.KubernetesComponent))
			urls = append(urls, url)
		}
	}
	return urls, nil
}

func (k kubernetesClient) Delete(url url) error {
	if url.GetKind() == INGRESS {
		return url.Delete()
	}
	return nil
}

func (k kubernetesClient) Create(url envinfo.EnvInfoURL, cmp component.OdoComponent) error {
	if url.Kind == envinfo.INGRESS {
		if kubeCmp, ok := cmp.(component.KubernetesComponent); ok {
			url := NewNonPushedIngress(&url, kubeCmp)
			return url.CreateOrUpdate()
		}
	}
	return nil
}

func URLPush(client urlClient) error {
	urls, _ := client.List()

	for _, url := range urls {
		if url.GetStatus().State == StateTypeLocallyDeleted {
			url.Delete()
		} else if url.GetStatus().State == StateTypeNotPushed {
			url.CreateOrUpdate()
		}
	}
	return nil
}
