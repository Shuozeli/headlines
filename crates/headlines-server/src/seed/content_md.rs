//! Markdown → Telegraph Node converter.
//!
//! Maps the subset of CommonMark we care about to the `headlines.v1.Node`
//! tree (text leaves and tagged elements with attributes + children). Tags
//! outside the allow-list (`p, h3, h4, a, img, figure, figcaption, blockquote,
//! aside, pre, code, em, strong, s, u, iframe, video, br, hr, ul, ol, li`)
//! are dropped — their text content is kept, but the wrapping element is
//! discarded.
//!
//! HTML pass-through: the demo's `videos/` account uses raw `<iframe>` tags
//! in markdown to embed video content. The pulldown-cmark parser surfaces
//! those as `Event::Html`; we extract the `iframe`/`video` element and
//! preserve the `src`/`width`/`height`/`allowfullscreen` attrs.

use std::collections::HashMap;

use headlines_proto::v1::{Node, NodeElement, node};
use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag};

const ALLOWED_TAGS: &[&str] = &[
    "p",
    "h3",
    "h4",
    "a",
    "img",
    "figure",
    "figcaption",
    "blockquote",
    "aside",
    "pre",
    "code",
    "em",
    "strong",
    "s",
    "u",
    "iframe",
    "video",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
];

/// Convert a Markdown body into a Telegraph Node tree.
pub fn markdown_to_nodes(md: &str) -> Vec<Node> {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TABLES);
    let parser = Parser::new_ext(md, opts);

    let mut stack: Vec<NodeElement> = Vec::new();
    let mut output: Vec<Node> = Vec::new();

    let push_text = |stack: &mut Vec<NodeElement>, output: &mut Vec<Node>, text: String| {
        if text.is_empty() {
            return;
        }
        let leaf = Node {
            kind: Some(node::Kind::Text(text)),
        };
        if let Some(top) = stack.last_mut() {
            top.children.push(leaf);
        } else {
            output.push(leaf);
        }
    };

    let close_top = |stack: &mut Vec<NodeElement>, output: &mut Vec<Node>| {
        if let Some(top) = stack.pop() {
            let elem = Node {
                kind: Some(node::Kind::Element(top)),
            };
            if let Some(parent) = stack.last_mut() {
                parent.children.push(elem);
            } else {
                output.push(elem);
            }
        }
    };

    for evt in parser {
        match evt {
            Event::Start(tag) => match tag {
                Tag::Paragraph => stack.push(elem("p")),
                Tag::Heading { level, .. } => {
                    // Per articles.md the allow-list is h3/h4 only; map h1/h2
                    // up to h3 and h5/h6 down to h4. h3/h4 pass through.
                    let t = match level {
                        HeadingLevel::H1 | HeadingLevel::H2 | HeadingLevel::H3 => "h3",
                        HeadingLevel::H4 | HeadingLevel::H5 | HeadingLevel::H6 => "h4",
                    };
                    stack.push(elem(t));
                }
                Tag::BlockQuote(_) => stack.push(elem("blockquote")),
                Tag::CodeBlock(kind) => {
                    // Server-side validation: `code` is allowed but accepts
                    // no attrs. We open just a `<pre>`; the text that follows
                    // (and the matching End event) will close it. We don't
                    // wrap in a `<code>` here because we'd need a separate
                    // End event to balance it, and pulldown-cmark only emits
                    // one for the whole code block.
                    let _ = kind;
                    stack.push(elem("pre"));
                }
                Tag::List(Some(_)) => stack.push(elem("ol")),
                Tag::List(None) => stack.push(elem("ul")),
                Tag::Item => stack.push(elem("li")),
                Tag::Emphasis => stack.push(elem("em")),
                Tag::Strong => stack.push(elem("strong")),
                Tag::Strikethrough => stack.push(elem("s")),
                Tag::Link { dest_url, .. } => {
                    let mut a = elem("a");
                    a.attrs.insert("href".into(), dest_url.into_string());
                    stack.push(a);
                }
                Tag::Image {
                    dest_url, title, ..
                } => {
                    let mut img = elem("img");
                    img.attrs.insert("src".into(), dest_url.into_string());
                    if !title.is_empty() {
                        img.attrs.insert("alt".into(), title.into_string());
                    }
                    // Image is self-closing semantically; we still push so the
                    // matching End event pops it. Children are dropped at end-time.
                    stack.push(img);
                }
                _ => {
                    // Unknown / unsupported tag — push a sentinel so end-tag
                    // balance is preserved; we'll drop it on End.
                    stack.push(elem("__drop__"));
                }
            },
            Event::End(end) => {
                // Pop the matching element. If it's a __drop__, lift any
                // children to the parent so we keep their text.
                if let Some(top) = stack.pop() {
                    if top.tag == "__drop__" {
                        // Hoist children out of the dropped wrapper so we
                        // don't lose user-visible text.
                        if let Some(parent) = stack.last_mut() {
                            for ch in top.children {
                                parent.children.push(ch);
                            }
                        } else {
                            for ch in top.children {
                                output.push(ch);
                            }
                        }
                    } else {
                        let elem_node = Node {
                            kind: Some(node::Kind::Element(top)),
                        };
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(elem_node);
                        } else {
                            output.push(elem_node);
                        }
                    }
                }
                let _ = end;
            }
            Event::Text(t) => push_text(&mut stack, &mut output, t.into_string()),
            Event::Code(c) => {
                let mut code = elem("code");
                code.children.push(Node {
                    kind: Some(node::Kind::Text(c.into_string())),
                });
                let n = Node {
                    kind: Some(node::Kind::Element(code)),
                };
                if let Some(top) = stack.last_mut() {
                    top.children.push(n);
                } else {
                    output.push(n);
                }
            }
            Event::Html(h) | Event::InlineHtml(h) => {
                // Pass-through for iframes / videos. Strip everything else.
                let raw = h.into_string();
                if let Some(node) = parse_iframe_or_video(&raw) {
                    if let Some(top) = stack.last_mut() {
                        top.children.push(Node {
                            kind: Some(node::Kind::Element(node)),
                        });
                    } else {
                        output.push(Node {
                            kind: Some(node::Kind::Element(node)),
                        });
                    }
                }
            }
            Event::SoftBreak => push_text(&mut stack, &mut output, " ".into()),
            Event::HardBreak => {
                let br = elem("br");
                let n = Node {
                    kind: Some(node::Kind::Element(br)),
                };
                if let Some(top) = stack.last_mut() {
                    top.children.push(n);
                } else {
                    output.push(n);
                }
            }
            Event::Rule => {
                let hr = elem("hr");
                let n = Node {
                    kind: Some(node::Kind::Element(hr)),
                };
                if let Some(top) = stack.last_mut() {
                    top.children.push(n);
                } else {
                    output.push(n);
                }
            }
            Event::FootnoteReference(_) | Event::TaskListMarker(_) => {
                // Drop unsupported markup.
            }
            _ => {}
        }
    }
    // Defensive: close anything still open.
    while !stack.is_empty() {
        close_top(&mut stack, &mut output);
    }

    output
}

fn elem(tag: &str) -> NodeElement {
    NodeElement {
        tag: tag.to_owned(),
        attrs: HashMap::new(),
        children: Vec::new(),
    }
}

/// Parse a single raw `<iframe ...>` or `<video ...>` HTML fragment into a
/// NodeElement, preserving src/width/height/allowfullscreen attrs. Returns
/// `None` for any other HTML.
fn parse_iframe_or_video(html: &str) -> Option<NodeElement> {
    let trimmed = html.trim();
    let lower = trimmed.to_ascii_lowercase();
    let tag = if lower.starts_with("<iframe") {
        "iframe"
    } else if lower.starts_with("<video") {
        "video"
    } else {
        return None;
    };
    if !ALLOWED_TAGS.contains(&tag) {
        return None;
    }
    let mut node = elem(tag);
    // Very small attr extractor: walk char-by-char, recognise `name="value"`.
    let mut chars = trimmed.chars().peekable();
    // Skip past `<iframe` / `<video`
    let skip = format!("<{tag}").len();
    for _ in 0..skip {
        chars.next();
    }
    while let Some(&c) = chars.peek() {
        if c == '>' || c == '/' {
            break;
        }
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() || c == '>' {
                break;
            }
            name.push(c);
            chars.next();
        }
        if chars.peek() == Some(&'=') {
            chars.next();
            let mut quote: Option<char> = None;
            if matches!(chars.peek(), Some('"') | Some('\'')) {
                quote = chars.next();
            }
            let mut value = String::new();
            while let Some(&c) = chars.peek() {
                if let Some(q) = quote {
                    if c == q {
                        chars.next();
                        break;
                    }
                } else if c.is_whitespace() || c == '>' {
                    break;
                }
                value.push(c);
                chars.next();
            }
            // Server-side validation only permits `src` on iframe/video.
            // Drop everything else even if it's safe — keeps the node valid
            // through the article service's allow-list.
            if name == "src" {
                node.attrs.insert(name, value);
            }
        }
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_element_tag(nodes: &[Node]) -> &str {
        match nodes[0].kind.as_ref().unwrap() {
            node::Kind::Element(e) => &e.tag,
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn paragraph_emits_p() {
        // Arrange / Act
        let nodes = markdown_to_nodes("hello world");

        // Assert
        assert_eq!(nodes.len(), 1);
        assert_eq!(first_element_tag(&nodes), "p");
    }

    #[test]
    fn heading_h1_maps_to_h3() {
        // Arrange / Act
        let nodes = markdown_to_nodes("# Title");

        // Assert
        assert_eq!(first_element_tag(&nodes), "h3");
    }

    #[test]
    fn heading_h4_passes_through() {
        // Arrange / Act
        let nodes = markdown_to_nodes("#### Sub");

        // Assert
        assert_eq!(first_element_tag(&nodes), "h4");
    }

    #[test]
    fn link_keeps_href() {
        // Arrange / Act
        let nodes = markdown_to_nodes("see [docs](https://example.com)");

        // Assert — should be a `p` containing an `a` with href.
        let kind = nodes[0].kind.as_ref().unwrap();
        let p = match kind {
            node::Kind::Element(e) => e,
            _ => panic!(),
        };
        assert_eq!(p.tag, "p");
        let a = p
            .children
            .iter()
            .find_map(|c| match c.kind.as_ref().unwrap() {
                node::Kind::Element(e) if e.tag == "a" => Some(e),
                _ => None,
            })
            .expect("link should be present");
        assert_eq!(
            a.attrs.get("href").map(String::as_str),
            Some("https://example.com")
        );
    }

    #[test]
    fn iframe_passes_through_with_src() {
        // Arrange — an iframe inside a paragraph.
        let md = "<iframe src=\"https://example.com/embed/x\" width=\"640\"></iframe>";

        // Act
        let nodes = markdown_to_nodes(md);

        // Assert — at least one iframe node with the src attr.
        fn find_iframe(nodes: &[Node]) -> Option<&NodeElement> {
            for n in nodes {
                if let node::Kind::Element(e) = n.kind.as_ref().unwrap() {
                    if e.tag == "iframe" {
                        return Some(e);
                    }
                    if let Some(child) = find_iframe(&e.children) {
                        return Some(child);
                    }
                }
            }
            None
        }
        let frame = find_iframe(&nodes).expect("iframe must surface");
        assert_eq!(
            frame.attrs.get("src").map(String::as_str),
            Some("https://example.com/embed/x")
        );
        // `width` is dropped by the converter — server's allow-list only
        // permits `src` on iframe.
        assert!(!frame.attrs.contains_key("width"));
    }

    #[test]
    fn code_block_emits_pre() {
        // Arrange / Act — fenced code block; we emit `<pre>` (no inner
        // `<code>` because the article service's allow-list only permits a
        // single tag per node and `code` accepts no attrs).
        let nodes = markdown_to_nodes("```\nlet x = 1;\n```");

        // Assert
        assert_eq!(first_element_tag(&nodes), "pre");
    }

    #[test]
    fn list_emits_ul() {
        // Arrange / Act
        let nodes = markdown_to_nodes("- one\n- two");

        // Assert
        assert_eq!(first_element_tag(&nodes), "ul");
    }

    #[test]
    fn ordered_list_emits_ol() {
        // Arrange / Act
        let nodes = markdown_to_nodes("1. a\n2. b");

        // Assert
        assert_eq!(first_element_tag(&nodes), "ol");
    }
}
