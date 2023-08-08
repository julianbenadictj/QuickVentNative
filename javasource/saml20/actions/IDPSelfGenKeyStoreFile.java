// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package saml20.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.security.KeyStoreHelper;
import saml20.proxies.ClaimMap;

public class IDPSelfGenKeyStoreFile extends CustomJavaAction<java.lang.Boolean>
{
	private IMendixObject __SSOConfiguration;
	private saml20.proxies.SSOConfiguration SSOConfiguration;
	private IMendixObject __keyStore;
	private saml20.proxies.KeyStore keyStore;
	private IMendixObject __ReloadSSOConfiguration;
	private saml20.proxies.SSOConfiguration ReloadSSOConfiguration;

	public IDPSelfGenKeyStoreFile(IContext context, IMendixObject SSOConfiguration, IMendixObject keyStore, IMendixObject ReloadSSOConfiguration)
	{
		super(context);
		this.__SSOConfiguration = SSOConfiguration;
		this.__keyStore = keyStore;
		this.__ReloadSSOConfiguration = ReloadSSOConfiguration;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		this.SSOConfiguration = this.__SSOConfiguration == null ? null : saml20.proxies.SSOConfiguration.initialize(getContext(), __SSOConfiguration);

		this.keyStore = this.__keyStore == null ? null : saml20.proxies.KeyStore.initialize(getContext(), __keyStore);

		this.ReloadSSOConfiguration = this.__ReloadSSOConfiguration == null ? null : saml20.proxies.SSOConfiguration.initialize(getContext(), __ReloadSSOConfiguration);

		// BEGIN USER CODE
		if (this.keyStore == null) {
			this.SSOConfiguration.setSSOConfiguration_KeyStore(null);
			KeyStoreHelper.generateSelfKeyPair(this.SSOConfiguration, getContext());
		} else if (ReloadSSOConfiguration != null && !ReloadSSOConfiguration.getEncryptionKeyLength().equals(SSOConfiguration.getEncryptionKeyLength())) {
			KeyStoreHelper.generateSelfKeyPair(this.SSOConfiguration, getContext());
		}
		return true;
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "IDPSelfGenKeyStoreFile";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
