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
					String gitDir = "/path/to/.git"; // FIXME
					List<byte[]> conditions = new ArrayList<>(messages.length);
					for (IHttpRequestResponse messageInfo : messages) {
						IHttpService hs = messageInfo.getHttpService();
						IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
						IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
						byte[] response = messageInfo.getResponse();
						byte[] contents = Arrays.copyOfRange(response,
								respInfo.getBodyOffset(), response.length);
						conditions.add(contents);
					}
					Set<RevCommit> cs = findCommits(gitDir, conditions);
					try (PrintStream ps = new PrintStream(stderr)) {
						ps.println(cs);
						ps.println(cs.size());
						List<RevCommit> cl = new ArrayList<>(cs);
						Collections.sort(cl, new Comparator<RevCommit>() {
							public int compare(RevCommit c1, RevCommit c2) {
								return c1.getCommitTime() - c2.getCommitTime();
							}
						});
						ps.println(cl.get(0)); // XXX az első, ami _már_ a keresett
						ps.println(cl.get(cl.size() - 1)); // XXX az utolsó, amig _még_ a keresett
					}
				} catch (Exception e) {
					reportError(e, "Git version error"); // FIXME
				}
			}
		});
		return Collections.singletonList(i);
	}

	private void reportError(Throwable t, String title) {
		if (title != null) JOptionPane.showMessageDialog(null, t.getMessage(),
				title, JOptionPane.ERROR_MESSAGE);
		t.printStackTrace(new PrintStream(stderr));
	}

	private static Set<RevCommit> findCommits(String gitDir,
			Iterable<byte[]> conditions) throws IOException, NoSuchAlgorithmException, GitAPIException {
		MessageDigest md = MessageDigest.getInstance("SHA");
		Set<RevCommit> commonCommits = null;
		try (Repository repository = new FileRepositoryBuilder().setGitDir(
					new File(gitDir)).build()) {
			try (Git git = new Git(repository)) {
				for (byte[] contents : conditions) {
					Set<RevCommit> matchingCommits = new HashSet<>();

					md.reset();
					String prefix = String.format("blob %d\0", contents.length);
					md.update(prefix.getBytes(StandardCharsets.US_ASCII));
					// TODO optimize this in Burp by computing it directly on the source byte[]
					ObjectId hash = ObjectId.fromRaw(md.digest(contents));

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
					}
					if (commonCommits.size() == 1) break; // TODO conflicting conditions?
				}
			}
		}
		return commonCommits;
	}
}
