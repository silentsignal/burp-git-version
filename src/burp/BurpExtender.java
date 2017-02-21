package burp;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import java.awt.event.*;
import javax.swing.*;

import org.eclipse.jgit.api.*;
import org.eclipse.jgit.api.errors.*;
import org.eclipse.jgit.lib.*;
import org.eclipse.jgit.storage.file.*;
import org.eclipse.jgit.revwalk.*;
import org.eclipse.jgit.treewalk.*;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	private IExtensionHelpers helpers;
	private OutputStream stderr;
	private final static String NAME = "Git version"; // FIXME

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		stderr = callbacks.getStderr();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Find version from git"); // FIXME
		i.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				try {
					JFileChooser chooser = new JFileChooser();
					chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
					chooser.setAcceptAllFileFilterUsed(false);
					chooser.setFileHidingEnabled(false); // .git is considered hidden
					if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
					File gitDir = chooser.getCurrentDirectory();
					File gitSubDir = new File(gitDir, ".git");
					if (gitSubDir.exists()) gitDir = gitSubDir;
					List<ObjectId> conditions = new ArrayList<>(messages.length);
					MessageDigest md = MessageDigest.getInstance("SHA");
					for (IHttpRequestResponse messageInfo : messages) {
						IHttpService hs = messageInfo.getHttpService();
						IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
						IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
						byte[] response = messageInfo.getResponse();
						int offset = respInfo.getBodyOffset();
						int length = response.length - offset;
						md.reset();
						String prefix = String.format("blob %d\0", length);
						md.update(prefix.getBytes(StandardCharsets.US_ASCII));
						md.update(response, offset, length);
						conditions.add(ObjectId.fromRaw(md.digest()));
					}
					Set<RevCommit> cs = findCommits(gitDir, conditions);
					try (PrintStream ps = new PrintStream(stderr)) {
						// TODO handle null
						// TODO measure timing
						ps.format("The specified files are present in %d commits.\n\n", cs.size());
						List<RevCommit> cl = new ArrayList<>(cs);
						Collections.sort(cl, new Comparator<RevCommit>() {
							public int compare(RevCommit c1, RevCommit c2) {
								return c2.getCommitTime() - c1.getCommitTime();
							}
						});
						reportCommit(ps, "first", cl.get(0));
						reportCommit(ps, "last", cl.get(cl.size() - 1));
						ps.format("\nThe full list of affected commits is below:\n\n%s", cl);
					}
				} catch (Exception e) {
					reportError(e, "Git version error"); // FIXME
				}
			}
		});
		return Collections.singletonList(i);
	}

	private static void reportCommit(PrintStream ps, String which, RevCommit commit) {
		ps.format("The %s commit that matches the observed file contents is ", which);
		ps.print(commit.abbreviate(10));
		ps.format(" which was committed at %s\n",
				new java.util.Date(commit.getCommitTime() * 1000L));
	}

	private void reportError(Throwable t, String title) {
		if (title != null) JOptionPane.showMessageDialog(null, t.getMessage(),
				title, JOptionPane.ERROR_MESSAGE);
		t.printStackTrace(new PrintStream(stderr));
	}

	private static Set<RevCommit> findCommits(File gitDir,
			Iterable<ObjectId> conditions) throws IOException, GitAPIException {
		Set<RevCommit> commonCommits = null;
		try (Repository repository = new FileRepositoryBuilder().setGitDir(gitDir).build()) {
			try (Git git = new Git(repository)) {
				for (ObjectId hash : conditions) {
					// TODO does the repository even contain the blob?
					//  - sanity check before going through commits/trees
					//  - would produce empty matchingCommits (see below)
					//  - skip hash / return with null (short circuit)?
					Set<RevCommit> matchingCommits = new HashSet<>();

					Iterable<RevCommit> commits = git.log().all().call();
					for (RevCommit commit : commits) {
						RevTree tree = commit.getTree();
						try (TreeWalk treeWalk = new TreeWalk(repository)) {
							treeWalk.addTree(tree);
							treeWalk.setRecursive(true);
							// TODO cache subtrees
							while (treeWalk.next()) {
								if (treeWalk.getObjectId(0).equals(hash)) {
									commit.disposeBody();
									matchingCommits.add(commit);
									break;
								}
							}
						}
					}

					if (commonCommits == null) {
						commonCommits = matchingCommits;
					} else {
						commonCommits.retainAll(matchingCommits);
						// TODO what if matchingCommits is empty?
						//  - return immediately / short circuit?
						//  - ignore file (see conflict below as well)
					}
					if (commonCommits.size() == 1) break; // TODO conflicting conditions?
				}
			}
		}
		return commonCommits;
	}
}
