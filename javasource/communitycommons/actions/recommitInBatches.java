// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package communitycommons.actions;

import communitycommons.Misc;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;

public class recommitInBatches extends CustomJavaAction<java.lang.Boolean>
{
	private java.lang.String xpath;
	private java.lang.Long batchsize;
	private java.lang.Boolean waitUntilFinished;
	private java.lang.Boolean ascending;

	public recommitInBatches(IContext context, java.lang.String xpath, java.lang.Long batchsize, java.lang.Boolean waitUntilFinished, java.lang.Boolean ascending)
	{
		super(context);
		this.xpath = xpath;
		this.batchsize = batchsize;
		this.waitUntilFinished = waitUntilFinished;
		this.ascending = ascending;
	}

	@java.lang.Override
	public java.lang.Boolean executeAction() throws Exception
	{
		// BEGIN USER CODE
		return Misc.recommitInBatches(xpath, batchsize.intValue(), waitUntilFinished.booleanValue(), ascending);
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "recommitInBatches";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
