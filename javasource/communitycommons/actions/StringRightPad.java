// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package communitycommons.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;

/**
 * Pads a string on the right to a certain length. 
 * value : the original value
 * amount: the desired length of the resulting string.
 * fillCharacter: the character to pad with. (or space if empty)
 * 
 * For example
 * StringRightPad("hello", 8, "-")  returns "hello---"
 * StringLeftpad("hello", 2, "-")  returns "hello"
 */
public class StringRightPad extends CustomJavaAction<java.lang.String>
{
	private java.lang.String value;
	private java.lang.Long amount;
	private java.lang.String fillCharacter;

	public StringRightPad(IContext context, java.lang.String value, java.lang.Long amount, java.lang.String fillCharacter)
	{
		super(context);
		this.value = value;
		this.amount = amount;
		this.fillCharacter = fillCharacter;
	}

	@java.lang.Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		return communitycommons.StringUtils.rightPad(value, amount, fillCharacter);
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "StringRightPad";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
